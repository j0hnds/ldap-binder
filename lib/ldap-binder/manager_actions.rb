module LdapBinder

  module ManagerActions

    #
    # If you want more/different attributes returned from a search, add/remove
    # attr names here.
    #
    SEARCH_RETURN_ATTRS = %w{ cn mail sn givenName description uid destinationIndicator pwdChangedTime pwdHistory pwdFailureTime createTimestamp ou businessCategory }

    #
    # The attribute mappings for users
    #
    USER_ATTR_MAPPING = {
      login: { ldap: 'cn', required: true },
      last: { ldap: 'sn', required: true },
      password: { ldap: 'userPassword', required: true },
      uuid: { ldap: 'uid', required: false },
      first: { ldap: 'givenName', required: false },
      email: { ldap: 'mail', required: false },
      note: { ldap: 'description', required: false },
      salt: { ldap: 'destinationIndicator', required: false },
      account_uid: { ldap: 'ou', required: false },
      application_uid: { ldap: 'businessCategory', required: false }
    }

    #
    # Performs a search for a user in the DT in a flexible way.
    # The search_criteria hash contains the criteria that will be used for the search. The
    # method selects the criteria to use in the following order:
    #
    # 1. :uuid - Unique user identifier (ldap: 'uid')
    # 2. :login - User login (ldap: 'cn')
    # 3. :token - Single signon token (ldap: 'userPassword' - clear text)
    # 4. :token and :account_uid - Single signon token and account identifier 
    #                               (ldap: 'userPassword' - clear text and
    #                                ldap: 'businessCategory')
    # 5. :email - User's email address
    #
    # Returns a hash of the users attributes (see SEARCH_RETURN_ATTRS) or nil
    # if the user isn't found.
    #
    def user_search(search_criteria)
      found_user = nil
      as_manager do | conn |
        conn.search(user_root_dn,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    ldap_user_search_criteria(search_criteria),
                    SEARCH_RETURN_ATTRS) do | entry |
          found_user = entry.to_hash
        end
      end
      found_user
    end

    def unique_attribute_available?(uuid, attr_name, attr_value)
      # (mail=julio@gmail.com)
      # or (if uuid is not nil)
      # (&(!(uid=d109226f-80cf-4cbe-b732-4bce59335f1b))(mail=julio@gmail.com))
      available = true
      attr_filter = "(#{attr_name}=#{attr_value})"
      filter = uuid.nil? ? attr_filter : "(&(!(uid=#{uuid}))#{attr_filter})"
      as_manager do | conn |
        conn.search(user_root_dn,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    filter,
                    %w{ uid }) do | entry |
          available = false # Anything found means the value is not available
        end
      end
      available
    end

    def all_uuids(uuids)
      uid_criteria = uuids.inject('') { | a, uuid | a << "(uid=#{uuid})" }
      any_uid = "(|#{uid_criteria})"
      users = []
      as_manager do | conn |
        conn.search(user_root_dn,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    any_uid,
                    SEARCH_RETURN_ATTRS) do | entry |
          users << entry.to_hash
        end
      end
      users
    end

    #
    # Adds a new user to the DT. user_info contains a hash of the user information.
    # The rules:
    #
    # 1. Required attributes are:
    #    :login ('cn')
    #    :last ('sn')
    #    :password ('userPassword')
    # 2. Optional attributes are:
    #    :first ('givenName')
    #    :email ('mail')
    #    :note ('description')
    #    :salt ('destinationIndicator') - use only when migrating existing users
    #    :account_uid ('ou')
    #    :application_uid ('businessCategory')
    # 
    # When successful, returns the 'dn' and 'uuid' of the newly created user. Raises
    # an exception on failure (LDAP::ResultError). 
    #
    # Assumes the data contained in the user_info hash is 'clean'. Any error will be related
    # to missing required fields, or other systemic problem.
    # 
    def add_user(user_info)
      raise MissingAttributeError.new(missing_required_attributes(user_info)), "Missing required attributes!" unless attributes_sufficient?(user_info)

      dn = nil
      uuid = nil
      as_manager do | conn |
        login = user_info[:login]
        dn = dn_from_login(login)
        uuid = create_unique_uuid(conn)
        password = user_info.has_key?(:salt) ? user_info[:password] : prepare_password(user_info[:password], create_salt(login))

        entry_set = attribute_entries_for_add(user_info.merge(password: password, uuid: uuid))

        conn.add(dn, entry_set)
      end
      { dn: dn, uuid: uuid }
    end

    #
    # Updates the attributes of the identified in the user_attributes. Since it is possible
    # that the login of the user is being modified by this method, it is necessary for the
    # :uuid of the user to be specified in the attributes. Be aware that the value of the
    # :uuid for a user CANNOT be modified. It's the only thing we have to hold onto for
    # identity.
    # 
    # The rules for modification:
    #
    # 1. If a :password is specified in the user_attributes, the user's password will be
    #    changed.
    # 2. For non-required attributes (:first, :last, :email, :note), if there is a value in
    #    user_attributes and there is no attribute in ldap, then it will be added to ldap.
    #    If the value is in the user_attributes and in ldap and the values are different,
    #    the value in ldap will be changed to match the value in user_attributes. If 
    #    there is no value in user_attributes and the attribute is present in ldap, it will
    #    be removed from ldap.
    # 3. If the login of the user has changed, the dn of the user will be modified to
    #    match the new cn value.
    #
    # Returns a hash of the dn and uuid of the user on success. Raises an exception if
    # an error occurred (LDAP::ResultError)
    #
    def update_user(user_attributes)
      user_info = user_search(user_attributes)
      raise UserNotFoundError.new(user_attributes), "User not found. Cannot update attributes." if user_info.nil?

      dn = user_info['dn'].first

      as_manager do | conn |
        new_entry = []

        update_entry(new_entry, user_info, user_attributes, 'givenName', :first)
        update_entry(new_entry, user_info, user_attributes, 'sn', :last)
        update_entry(new_entry, user_info, user_attributes, 'mail', :email)
        update_entry(new_entry, user_info, user_attributes, 'description', :note)

        if user_attributes.has_key?(:password)
          # A little different. If the password is not present, we don't do anything. If it
          # is, we replace it with the new one.
          new_entry << LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'userPassword', [ prepare_password(user_attributes[:password], create_salt(user_attributes[:login])) ])
        end
        
        # First, modify the user's attributes as long as we have the user's
        # dn in our hands...
        conn.modify(dn, new_entry)

        # Now take care of modifying the login if necessary
        if user_attributes.has_key?(:login)
          if user_attributes[:login] != user_info['cn'].first
            # Ugh. They want to change the login. Losers.
            conn.modrdn(dn,
                        "cn=#{user_attributes[:login]}",
                        true) # delete the old RDN
            dn = ([ "cn=#{user_attributes[:login]}" ] + dn.split(',')[1..-1]).join(',')
          end
        end

      end
      { dn: dn, uuid: user_info['uid'].first }
    end

    # 
    # Deletes all users from the system
    #
    def delete_all_users
      all_dns = []
      as_manager do | conn |
        conn.search(user_root_dn,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    '(objectClass=inetOrgPerson)',
                    %w{ cn }) do | entry |
          all_dns << entry.dn
          conn.delete(entry.dn)
        end
      end
      all_dns
    end

    def link_user(user_ident, link_to)
      user_info = user_search(user_ident)
      raise UserNotFoundError.new(user_ident), "Cannot find user to link" if user_info.nil?
      dn = user_info['dn'].first
      uuid = user_info['uid'].first

      account = link_to[:account_uid]
      application = link_to[:application_uid]

      if account || application
        # No point in doing anything unless at least one of the two
        # is set to something
        entry = []
        entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'businessCategory', application.is_a?(Array) ? application : [ application ]) unless application.nil?
        entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'ou', account.is_a?(Array) ? account : [ account ]) unless account.nil?
        as_manager do | conn |
          conn.modify(dn, entry)
        end
                          
      end
      { dn: dn, uuid: uuid }
    end

    def delete_user(user_ident)
      dn = user_ident[:dn] if user_ident.has_key?(:dn)
      if dn.nil?
        user_info = user_search(user_ident)
        raise UserNotFoundError.new(user_ident), "Cannot find user to delete" if user_info.nil?
        dn = user_info['dn'].first
      end

      as_manager do | conn |
        conn.delete(dn)
      end
      dn
    end

    def unlink_user(uuid, link_attributes) 
      application = link_attributes[:application_uid]
      account = link_attributes[:account_uid]
      return nil if application.nil? && account.nil?

      user_info = user_search(uuid: uuid)
      raise UserNotFoundError.new(uuid: uuid), "Cannot find user to unlink" if user_info.nil?
      
      dn = user_info['dn'].first
      
      ldap_accounts = user_info['ou'].nil? ? [] : user_info['ou']
      ldap_applications = user_info['businessCategory'].nil? ? [] : user_info['businessCategory']

      num_accounts = ldap_accounts.size
      num_applications = ldap_applications.size

      # Cool, we found the user, now let's see what's what
      if account.is_a?(Array)
        application.compact.each { | acct | ldap_accounts.delete(acct) }
      else
        ldap_accounts.delete(account) unless account.nil?
      end
      if application.is_a?(Array)
        application.compact.each { | app | ldap_applications.delete(app) }
      else
        ldap_applications.delete(application) unless application.nil?
      end

      if ldap_accounts.size < num_accounts || ldap_applications.size < num_applications
        # Something changed
        as_manager do | conn |
          if ldap_accounts.empty? || ldap_applications.empty?
            # Need to delete
            conn.delete(dn)
          else
            # Need to update with new values
            entry = []
            entry << LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'ou', ldap_accounts)
            entry << LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'businessCategory', ldap_applications)

            conn.modify(dn, entry)
          end
        end
      end
      dn
    end

    private

    #
    # Invokes the specified block as the ldap_manager. The
    # block is passed the bound ldap connection.
    #
    # If unable to bind the manager, an LDAP::Error is raised.
    #
    def as_manager
      bind(current_configuration['manager-dn'], current_configuration['manager-pw']) do | conn |
        yield conn
      end
    rescue LDAP::Error => ex
      raise BindError.new(nil, ex), "Error binding manager"
    end
    
    # TODO: Refactor target
    def ldap_user_search_criteria(search_criteria)
      if search_criteria.has_key?(:uuid)
        "(uid=#{search_criteria[:uuid]})"
      elsif search_criteria.has_key?(:login)
        "(cn=#{search_criteria[:login]})"
      elsif search_criteria.has_key?(:token)
        filter = "(userPassword=#{search_criteria[:token]})"
        if search_criteria.has_key?(:account_uid) && !search_criteria[:account_uid].nil?
          filter = "(&#{filter}(ou=#{search_criteria[:account_uid]}))"
        end
        filter
      elsif search_criteria.has_key?(:email)
        "(mail=#{search_criteria[:email]})"
      else
        raise "Invalid search criteria"
      end
    end

    #
    # Appends an LDAP.mod entry to the entry array based on the key/values
    # specified in the parameters. It is possible for no changes to be made
    # in the entry array.
    #
    def update_entry(entry, ldap_attrs, user_attrs, ldap_key, user_key)
      if user_attrs.has_key?(user_key)
        if ldap_attrs.has_key?(ldap_key)
          if user_attrs[user_key] != ldap_attrs[ldap_key].first
            entry << LDAP.mod(LDAP::LDAP_MOD_REPLACE, ldap_key, [ user_attrs[user_key] ])
          end
        else
          entry << LDAP.mod(LDAP::LDAP_MOD_ADD, ldap_key, [ user_attrs[user_key] ])
        end
      else
        if ldap_attrs.has_key?(ldap_key)
          entry << LDAP.mod(LDAP::LDAP_MOD_DELETE, ldap_key, [ ])
        end
      end
    end

    #
    # Creates a new, unique uuid for a user
    #
    def create_unique_uuid(conn)
      loop do
        uuid = SecureRandom.uuid
        break uuid unless uuid_exists?(conn, uuid)
      end
    end

    #
    # Returns true if the specified uuid already exists in the DT
    #
    def uuid_exists?(conn, uuid)
      found = false
      conn.search(user_root_dn,
                  LDAP::LDAP_SCOPE_SUBTREE,
                  "(uid=#{uuid})",
                  %w{ uid }) { | entry | found = true }
      found
    end

    #
    # Return true if the user_attributes hash contains values for all required
    # attributes
    #
    def attributes_sufficient?(user_attributes)
      missing_required_attributes(user_attributes).empty?
    end

    def missing_required_attributes(user_attributes)
      required_attrs = USER_ATTR_MAPPING.select { | key, value | value[:required] }.keys
      populated_attrs = non_empty_attributes(user_attributes).keys
      (required_attrs - populated_attrs)
    end

    def non_empty_attributes(user_attributes)
      user_attributes.select do | key, value | 
        !(value.nil? || (value.instance_of?(String) && value.size == 0) || (value.instance_of?(Array) && value.compact.size == 0))
      end
    end

    def attribute_entries_for_add(user_attributes)
      entry = [ LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectClass', [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ]) ]

      non_empty_attributes(user_attributes).each do | attr, value |
        next unless USER_ATTR_MAPPING.has_key?(attr)
        entry << LDAP.mod(LDAP::LDAP_MOD_ADD, USER_ATTR_MAPPING[attr][:ldap], user_attributes[attr].is_a?(Array) ? user_attributes[attr] : [ user_attributes[attr] ])
      end

      entry          
    end

  end

end
