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
    
    def search(search_criteria)
      found_user = nil
      as_manager do | conn |
        conn.search(search_base,
                    LDAP::LDAP_SCOPE_SUBTREE,
                    ldap_user_search_criteria(search_criteria),
                    %w{ cn uid destinationIndicator pwdChangedTime pwdFailureTime createTimestamp }) do | entry |
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

    def add_user(user_info)
      
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
      if search_criteria.has_key?(:login)
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
      "{SSHA}" + Base64.encode64("#{pwdigest}#{salt}").chomp!
    end
  end

end
