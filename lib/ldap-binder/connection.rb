module LdapBinder

  class Connection
    include Singleton

    # Configuration hash must look like:
    #
    # {
    #   'production => {
    #                    'host' => 'www.something.com',
    #                    'port' => 389,
    #                    'manager-dn' => 'cn=Manager,dc=providigm,dc=com',
    #                    'manager-pw' => 'test1234',
    #                    'user-subgroup-ou' => 'ou=production',
    #                    'root-dn' => 'dc=providigm,dc=com',
    #                    'application-users-ou' => 'ou=applicationUsers' 
    #                  },
    #   'development' => {},
    #   'test' => {}
    # }
    #                    

    DEFAULT_CONFIG_PATH = "config/ldap.yml"
    DEFAULT_CONFIG_BASE_PATH = "."
    DEFAULT_ENVIRONMENT = 'development'

    AUTH_STRATEGIES = [
                       { valid: ->(criteria) { criteria.has_key?(:login) && criteria.has_key?(:password) },
                         method: :standard_bind },
                       { valid: ->(criteria) { criteria_has_key?(:token) },
                         method: :sso_bind }
                      ]

    class << self

      attr_writer :config_path, :config_base_path, :environment

      def config_path
        @config_path ||= DEFAULT_CONFIG_PATH
      end

      def config_base_path
        @config_base_path ||= defined?(Rails) ? Rails.root.to_s : DEFAULT_CONFIG_BASE_PATH
      end

      def environment
        @environment ||= defined?(Rails) ? Rails.env : DEFAULT_ENVIRONMENT
      end

      def conn
        @conn ||= self.instance
      end

    end

    def ldap_connection
      if @ldap_connection.nil?
        config = current_configuration
        @ldap_connection = LDAP::Conn.new(config['host'], config['port'])
      end
      @ldap_connection
    end

    ############################################################
    # Potential abstraction
    ############################################################

    def as_manager
      bind(current_configuration['manager-dn'], current_configuration['manager-pw']) do | conn |
        yield conn
      end
    end

    def as_user(login, password)
      bind(dn_from_login(login), password) do | conn |
        yield conn
      end
    end
    
    def search(search_criteria)
      found_user = nil
      as_manager do | conn |
        conn.search(search_base,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    ldap_user_search_criteria(search_criteria),
                    %w{ cn mail sn givenName description uid destinationIndicator pwdChangedTime pwdHistory pwdFailureTime createTimestamp }) do | entry |
          found_user = entry.to_hash
        end
      end
      found_user
    end

    def authenticate(authentication_criteria)
      user_data = search(authentication_criteria)
      if user_data
        # Found the user
        perform_user_bind(user_data, authentication_criteria)
      end
      user_data
    end

    def password_in_history?(pwd_history, new_password)
      pwd_history.detect do | pw_entry |
        old_hash = pw_entry[pw_entry.index("{SSHA}")..-1]
        old_salt = Base64.decode64(old_hash[6..-1])[-40..-1]
        new_hash = prepare_password(new_password, old_salt)
        old_hash == new_hash
      end
    end

    def change_password(login, old_password, new_password)
      user_info = search(login: login) # get the data about the user
      as_user(login, old_password) do | conn |
        # OK, successfully logged in, now let's make sure the new password has not
        # already been used
        raise "Password cannot be used again so soon" if password_in_history?(user_info['pwdHistory'], new_password)
        entry = [ LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'userPassword', [ prepare_password(new_password, create_salt(login)) ]) ]
        conn.modify(dn_from_login(login), entry)
      end
    end

    def add_user(user_info)
      dn = nil
      uuid = nil
      as_manager do | conn |
        login = user_info[:login]
        dn = dn_from_login(login)
        uuid = create_unique_uuid(conn)

        new_entry = [
                     LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectClass', [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ]),
                     LDAP.mod(LDAP::LDAP_MOD_ADD, 'cn', [ login ]),
                     LDAP.mod(LDAP::LDAP_MOD_ADD, 'sn', [ user_info[:last] ]),
                     LDAP.mod(LDAP::LDAP_MOD_ADD, 'uid', [ uuid ]),
                     LDAP.mod(LDAP::LDAP_MOD_ADD, 'userPassword', [ prepare_password(user_info[:password], create_salt(login)) ]),
                    ]
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'givenName', [ user_info[:first] ]) if user_info.has_key?(:first)
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'mail', [ user_info[:email] ]) if user_info.has_key?(:email)
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'description', [ user_info[:note] ]) if user_info.has_key?(:note)
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'destinationIndicator', [ user_info[:salt] ]) if user_info.has_key?(:salt)
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'ou', [ user_info[:account_uid] ]) if user_info.has_key?(:account_uid)
        new_entry << LDAP.mod(LDAP::LDAP_MOD_ADD, 'businessCategory', [ user_info[:application] ]) if user_info.has_key?(:application)

        conn.add(dn, new_entry)
      end
      { dn: dn, uuid: uuid }
    end

    def update_user(user_attributes)
      user_info = search(user_attributes)
      raise "User not found. Cannot update attributes: #{user_attributes}" if user_info.nil?

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
        
        conn.modify(user_info['dn'].first, new_entry)

        # Now take care of modifying the login if necessary
        if user_attributes.has_key?(:login)
          if user_attributes[:login] != user_info['cn'].first
            # Ugh. They want to change the login. Losers.
            conn.modrdn(user_info['dn'].first,
                        "cn=#{user_attributes[:login]}",
                        true) # delete the old RDN
          end
        end

      end
    end

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
          entry << LDAP.mod(LDAP::LDAP_MOD_DELETE, ldap_key ) # , [ user_attrs[user_key] ])
        end
      end
    end

    def dn_from_login(login)
      "cn=#{login},#{search_base}"
    end

    def create_unique_uuid(conn)
      loop do
        uuid = SecureRandom.uuid
        break uuid unless uuid_exists?(conn, uuid)
      end
    end

    def uuid_exists?(conn, uuid)
      found = false
      conn.search(search_base,
                  LDAP::LDAP_SCOPE_SUBTREE,
                  "(uid=#{uuid})",
                  %w{ uid }) { | entry | found = true }
      found
    end

    
    ############################################################
    # Potential abstraction
    ############################################################

    def method_missing(method_name, *args, &block)
      if ldap_connection.respond_to?(method_name)
        ldap_connection.send(method_name, *args, &block)
      else
        super
      end
    end

    private

    def ldap_user_search_criteria(search_criteria)
      if search_criteria.has_key?(:uuid)
        "(uid=#{search_criteria[:uuid]})"
      elsif search_criteria.has_key?(:login)
        "cn=#{search_criteria[:login]}"
      elsif search_criteria.has_key?(:token)
        filter = "(userPassword=#{search_criteria[:token]})"
        if search_criteria.has_key?(:account_uuid)
          filter = "(&#{filter}(businessCategory=#{search_criteria[:account_uuid]}))"
        end
        filter
      else
        raise "Invalid search criteria"
      end
    end

    def search_base
      # ou=production,ou=applicationUsers,dc=providigm,dc=com
      "#{current_configuration['user-subgroup-ou']},#{current_configuration['application-users-ou']},#{current_configuration['root-dn']}"
    end

    def current_configuration
      if @current_configuration.nil?
        raise "Unable to find configuration file: #{full_configuration_path}" unless File.exists?(full_configuration_path)
        full_config = YAML.load(File.open(full_configuration_path, "r"))
        raise "No configuration found for environment: #{self.class.environment}" unless full_config.has_key?(self.class.environment)
        @current_configuration = full_config[self.class.environment]
      end
      @current_configuration
    end

    def full_configuration_path
      @full_config_path ||= File.join(self.class.config_base_path, self.class.config_path)
    end

    def perform_user_bind(user_data, criteria)
      strategy = AUTH_STRATEGIES.detect { | strat | strat[:valid].call(criteria) }
      raise "No strategy found for criteria: #{criteria.inspect}" if strategy.nil?
      send(strategy[:method], user_data, criteria)
    end

    def standard_bind(user_data, criteria)
      password = criteria[:password]
      dn = user_data['dn'].first
      if user_data.has_key?('destinationIndicator')
        # Has salt. Must be dealing with old password hash model
        salt = user_data['destinationIndicator'].first
        encrypted_password = Digest::SHA1.hexdigest("--#{salt}--#{password}--")
        bind(dn, encrypted_password) do | conn |
          update_entry_to_new_password_type(conn, dn, password, salt)
        end
      else
        bind(dn, password) { | conn | }
      end
    end

    def sso_bind(user_data, criteria)
      password = criteria[:token]
      dn = user_data['dn'].first
      bind(dn, password) { | conn | }
    end

    def update_entry_to_new_password_type(conn, dn, password, salt)
      # Now, we want to update the entry to remove the old salt and to establish
      # a standard mech for the password.
      modEntry = [
                  LDAP.mod(LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES, 'userPassword', [ prepare_password(password, salt) ]),
                  LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'destinationIndicator', [ ])
               ]
      conn.modify(dn, modEntry)
    end

    def prepare_password(password, salt=create_salt)
      pwdigest = Digest::SHA1.digest("#{password}#{salt}")
      puts "PW Digest: #{pwdigest}"
      puts "Salt: #{salt}"
      "{SSHA}" + Base64.encode64("#{pwdigest}#{salt}").chomp!.tap { | s | puts "HASH = #{s}" }
    end

    def create_salt(login='default_login')
      Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{login}--")
    end

  end

end
