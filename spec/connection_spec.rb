require 'spec_helper'

class BogusRails
end

describe LdapBinder::Connection do

  after(:each) do
    Object.send(:remove_const, :Rails) if defined?(Rails)
  end

  context "Class Methods" do

    context '::config_path' do
      
      before(:each) do
        LdapBinder::Connection.config_path = nil
      end

      after(:each) do
        LdapBinder::Connection.config_path = nil
      end

      it "should return the default value if not set" do
        expect(LdapBinder::Connection.config_path).to eq("config/ldap.yml")
      end

      it "should return the value specified" do
        LdapBinder::Connection.config_path = 'something/else.yml'
        expect(LdapBinder::Connection.config_path).to eq("something/else.yml")
      end

    end

    context '::config_base_path' do

      before(:each) do
        LdapBinder::Connection.config_base_path = nil
      end

      after(:each) do
        LdapBinder::Connection.config_base_path = nil
      end

      it "should return the default base path if not set and no Rails present" do
        expect(LdapBinder::Connection.config_base_path).to eq('.')
      end

      it "should return the Rails root path if Rails namespace is present" do
        Rails = BogusRails
        Rails.should_receive(:root).and_return('/usr/local/RailsProject')
        expect(LdapBinder::Connection.config_base_path).to eq('/usr/local/RailsProject')
      end

      it "should return the specified base path even if Rails is specified" do
        LdapBinder::Connection.config_base_path = '/another/path'
        Rails = BogusRails
        Rails.should_not_receive(:root)
        expect(LdapBinder::Connection.config_base_path).to eq('/another/path')
      end

    end

    context '::environment' do

      before(:each) do
        LdapBinder::Connection.environment = nil
      end

      after(:each) do
        LdapBinder::Connection.environment = nil
      end

      it "should return the default value if not set or Rails is not present" do
        expect(LdapBinder::Connection.environment).to eq("development")
      end

      it "should return the current Rails environment if Rails is present" do
        Rails = BogusRails
        Rails.should_receive(:env).and_return('production')
        expect(LdapBinder::Connection.environment).to eq('production')
      end

      it "should return the specified environment even if Rails is present" do
        LdapBinder::Connection.environment = 'test'
        Rails = BogusRails
        Rails.should_not_receive(:env)
        expect(LdapBinder::Connection.environment).to eq('test')
      end

    end

    context '::conn' do

      it "should return a singleton instance, but only the first time" do
        m_instance = double(LdapBinder::Connection)
        LdapBinder::Connection.should_receive(:instance).exactly(1).times.and_return(m_instance)

        expect(LdapBinder::Connection.conn).to be(m_instance)
        expect(LdapBinder::Connection.conn).to be(m_instance)
      end

    end

  end

  context 'Instance Methods' do

    let(:binder_connection) { LdapBinder::Connection.instance }

    context 'Public Methods' do

      context '#method_missing' do

        it "should respond to a bind method" do

          m_ld_connection = double("LdapConn")
          m_ld_connection.should_receive(:bind).with("cn=Manager,dc=providigm,dc=com", "test1234")
          binder_connection.stub(:ldap_connection).and_return(m_ld_connection)
          
          binder_connection.bind("cn=Manager,dc=providigm,dc=com", "test1234")
        end

      end

    end

    context 'Private Methods' do

      context '#full_configuration_path' do

        it "should return the full path to the configuration file" do
          expect(binder_connection.send(:full_configuration_path)).to eq("./config/ldap.yml")
        end

      end

      context '#current_configuration' do

        it "should raise an exception if unable to find the configuration file" do
          expect { binder_connection.send(:current_configuration) }.to raise_error
        end

        context "with valid configuration file" do

          before(:each) do
            File.stub(:exists?).and_return(true)
            @m_config_file = double("ConfigFile")
            File.stub(:open).and_return(@m_config_file)
            # config_hash = { 'development' => { 'host' => 'kanga', 'port' => 389 }, 'production' => { 'host' => 'www', 'port' => 389 }, 'test' => { 'host' => 'uat', 'port' => 389 } }
            # YAML.stub(:load).with(m_config_file).and_return(config_hash)
          end
          
          # after(:each) do
          #   # File.unstub(:exists?)
          #   LdapBinder::Connection.environment = nil
          # end

          it "should return the section of the configuration for the current environment" do
            config_hash = { 'development' => { 'host' => 'kanga', 'port' => 389 }, 'production' => { 'host' => 'www', 'port' => 389 }, 'test' => { 'host' => 'uat', 'port' => 389 } }
            YAML.stub(:load).with(@m_config_file).and_return(config_hash)
            expect(binder_connection.send(:current_configuration)).to eq({ 'host' => 'kanga', 'port' => 389 })
          end

          # it "should raise an exception if the current environment doesn't exist in the configuration file" do
          #   config_hash = { 'something_else' => { 'host' => 'kanga', 'port' => 389 } }
          #   YAML.stub(:load).with(@m_config_file).and_return(config_hash)
          #   # LdapBinder::Connection.environment = 'missing_environment'
          #   # LdapBinder::Connection.stub(:environment).and_return('missing_environment')
          #   # puts binder_connection.send(:current_configuration).inspect
          #   expect { binder_connection.send(:current_configuration) }.to raise_error
          # end
        end

      end

    end

  end

end
