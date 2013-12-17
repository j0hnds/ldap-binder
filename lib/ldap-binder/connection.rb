module LdapBinder

  class Connection
    include Singleton
    include ManagerActions # For actions performed by managers
    include UserActions    # For actions performed by users
    include CryptoSupport  # Some crypto support methods

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

      def mgr
        @mgr ||= self.instance
      end

    end

    def ldap_connection
      if @ldap_connection.nil?
        config = current_configuration
        @ldap_connection = LDAP::Conn.new(config['host'], config['port'])
      end
      @ldap_connection
    end

    # 
    # The dn of the organizational unit that holds all the users. This
    # can be used as the search base for an ldap user search or as the
    # dn of a user when combined with the user's cn.
    #
    def user_root_dn
      "#{current_configuration['user-subgroup-ou']},#{current_configuration['application-users-ou']},#{current_configuration['root-dn']}"
    end

    #
    # Returns the full dn for a user based on the login. The dn of a user is always
    # going to be rooted at the value returned from 'user_root_dn'.
    #
    def dn_from_login(login)
      "cn=#{login},#{user_root_dn}"
    end

    #
    # Delegates unknown method names to the current ldap connection. It blows
    # if the method is not known by the ldap connection either.
    #
    def method_missing(method_name, *args, &block)
      if ldap_connection.respond_to?(method_name)
        ldap_connection.send(method_name, *args, &block)
      else
        super
      end
    end

    private

    #
    # Returns the current configuration for LDAP connection.
    #
    def current_configuration
      if @current_configuration.nil?
        raise "Unable to find configuration file: #{full_configuration_path}" unless File.exists?(full_configuration_path)
        full_config = YAML.load(File.open(full_configuration_path, "r"))
        raise "No configuration found for environment: #{self.class.environment}" unless full_config.has_key?(self.class.environment)
        @current_configuration = full_config[self.class.environment]
      end
      @current_configuration
    end

    #
    # Returns the full path to the configuration file
    #
    def full_configuration_path
      @full_config_path ||= File.join(self.class.config_base_path, self.class.config_path)
    end

  end

end
