module LdapBinder

  module UserActions

    AUTH_STRATEGIES = [
                       { valid: ->(criteria) { criteria.has_key?(:login) && criteria.has_key?(:password) },
                         method: :standard_bind },
                       { valid: ->(criteria) { criteria.has_key?(:token) },
                         method: :sso_bind }
                      ]


    #
    # Provides a flexible means of authenticating a user against LDAP
    #
    def authenticate(authentication_criteria)
      user_data = user_search(authentication_criteria)
      if user_data
        # Found the user
        perform_user_bind(user_data, authentication_criteria)
        # Successful bind (no exception)
        # Refresh the user data based on successful login
        user_data = user_search(uuid: user_data['uid'].first)
      end
      user_data.nil? ? nil : user_data.merge(status: true)
    end

    #
    # Provides a means for a user to change his/her password.
    #
    def change_password(login, old_password, new_password)
      user_info = user_search(login: login) # get the data about the user
      raise UserNotFoundError.new(login: login), "Unable to find user to change password for" if user_info.nil?

      as_user(login, old_password) do | conn |
        # OK, successfully logged in, now let's make sure the new password has not
        # already been used
        raise PasswordHistoryError, "Password cannot be used again so soon" if password_in_history?(user_info['pwdHistory'], new_password)
        entry = [ LDAP.mod(LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES, 'userPassword', [ prepare_password(new_password, create_salt(login)) ]) ]
        conn.modify(dn_from_login(login), entry)
      end

      user_info
    end

    private
    
    #
    # Binds to ldap using the specified login/password, then
    # executes the specified block in the context of the bound connection.
    # Passes the bound connection to the block.
    # 
    # If unable to bind the user, an LDAP::Error is raised.
    #
    def as_user(login, password)
      bind(dn_from_login(login), password) do | conn |
        yield conn
      end
    rescue LDAP::Error => ex
      raise BindError.new(nil, ex), "Error binding manager"
    end

    #
    # Based on the specified criteria, this method identifies the specific
    # authentication strategy to use (see AUTH_STRATEGIES), then invokes the
    # method associated with that strategy.
    #
    # If no strategy is found that matches the criteria, a RuntimeError is raised.
    #
    def perform_user_bind(user_data, criteria)
      strategy = AUTH_STRATEGIES.detect { | strat | strat[:valid].call(criteria) }
      raise NoAuthStrategyFoundError.new(criteria), "No auth strategy found for criteria" if strategy.nil?
      send(strategy[:method], user_data, criteria)
    rescue LDAP::Error => ex
      user_data = user_search(uuid: user_data['uid'].first)
      raise BindError.new(user_data.merge!(status: false), ex), "Error binding user"
    end

    #
    # The authentication strategy is used when the criteria contains :login and :password
    # values. The challenge here is that it is possible that the user in LDAP may have
    # a password that was salted in a way that LDAP cannot deal with. The way we identify
    # this state is when the user_data has a 'destinationIndicator' attribute. Once we
    # authenticate using the old password, we reconstruct the password to be ldap
    # compatible and set it on the user.
    #
    def standard_bind(user_data, criteria)
      password = criteria[:password]
      dn = user_data['dn'].first
      if user_data.has_key?('destinationIndicator')
        # Has salt. Must be dealing with old password hash model
        salt = user_data['destinationIndicator'].first
        encrypted_password = custom_password_hasher.call(password, salt)
        bind(dn, encrypted_password) do | conn |
          update_entry_to_new_password_type(conn, dn, password, salt)
        end
      else
        bind(dn, password) { | conn | }
      end
    end

    #
    # This authentication strategy is used then a :token is specified. This
    # token is assumed to be the password.
    #
    def sso_bind(user_data, criteria)
      password = criteria[:token]
      dn = user_data['dn'].first
      bind(dn, password) { | conn | }
    end

    #
    # Converts an old-style non-compatible password to an ldap-compatible
    # password.
    #
    def update_entry_to_new_password_type(conn, dn, password, salt)
      # Now, we want to update the entry to remove the old salt and to establish
      # a standard mech for the password.
      modEntry = [
                  LDAP.mod(LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES, 'userPassword', [ prepare_password(password, salt) ]),
                  LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'destinationIndicator', [ ])
               ]
      conn.modify(dn, modEntry)
    end

    #
    # Checks to see if the specified password has already been used in the user's
    # password history.
    #
    def password_in_history?(pwd_history, new_password)
      return false if pwd_history.nil?
      pwd_history.detect do | pw_entry |
        old_hash = pw_entry[pw_entry.index("{SSHA}")..-1]
        old_salt = Base64.decode64(old_hash[6..-1])[-40..-1]
        new_hash = prepare_password(new_password, old_salt)
        old_hash == new_hash
      end
    end


  end

end
