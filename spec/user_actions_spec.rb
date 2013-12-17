require 'spec_helper'

class LdapBinder::TestUserActions
  include LdapBinder::UserActions

end

describe LdapBinder::TestUserActions do
  let(:cut) { LdapBinder::TestUserActions.new }

  context 'Public Methods' do

    context '#authenticate' do

      it "should return the data found for the user if the user was able to bind to ldap" do
        user_data = {}
        auth_criteria = { login: 'joe', password: 'abc123' }
        cut.
          should_receive(:user_search).
          with(auth_criteria).
          and_return(user_data)

        cut.
          should_receive(:perform_user_bind).
          with(user_data, auth_criteria)

        expect(cut.authenticate(auth_criteria)).to eq(user_data)
      end

      it "should return nil if the user wasn't found" do
        auth_criteria = { login: 'joe', password: 'abc123' }
        cut.
          should_receive(:user_search).
          with(auth_criteria).
          and_return(nil)

        expect(cut.authenticate(auth_criteria)).to be_nil
      end

      it "should raise a BindError if the user was unable to bind" do
        user_data = {}
        auth_criteria = { login: 'joe', password: 'abc123' }
        cut.
          should_receive(:user_search).
          with(auth_criteria).
          and_return(user_data)

        cut.
          should_receive(:perform_user_bind).
          with(user_data, auth_criteria).
          and_raise(LdapBinder::BindError)

        expect { cut.authenticate(auth_criteria) }.to raise_error(LdapBinder::BindError)
      end

    end

    context '#change_password' do

      it "should raise an BindError if the user wasn't able to bind to ldap" do
        user_info = {}

        cut.
          should_receive(:user_search).
          with(login: 'joe').
          and_return(user_info)

        cut.
          should_receive(:as_user).
          with('joe', 'abc123').
          and_raise(LdapBinder::BindError)

        expect { cut.change_password('joe', 'abc123', 'bcd234') }.to raise_error(LdapBinder::BindError)
      end

      it "should raise a UserNotFoundError if the user wasn't found in the DT" do
        cut.
          should_receive(:user_search).
          with(login: 'joe').
          and_return(nil)

        expect { cut.change_password('joe', 'abc123', 'bcd234') }.to raise_error(LdapBinder::UserNotFoundError)
      end

      it "should raise a PasswordHistoryError if the user is attempting to reuse a password too soon" do
        user_info = { 'pwdHistory' => [ 'old_password' ]}

        m_conn = double("LDAP::Connection")

        cut.
          should_receive(:user_search).
          with(login: 'joe').
          and_return(user_info)

        cut.
          should_receive(:as_user).
          with('joe', 'abc123').
          and_yield(m_conn)

        cut.
          should_receive(:password_in_history?).
          with([ 'old_password' ], 'bcd234').
          and_return(true)

        expect { cut.change_password('joe', 'abc123', 'bcd234') }.to raise_error(LdapBinder::PasswordHistoryError)
      end

      it "should return the user information if successfully changed the password" do
        user_info = {
        }
        
        m_entry = double("LDAP::Entry")

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:modify).
          with('cn=joe,dc=com', [ m_entry ])

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES, 'userPassword', [ '{SSHA}the_password' ]).
          and_return(m_entry)

        cut.
          should_receive(:user_search).
          with(login: 'joe').
          and_return(user_info)

        cut.
          should_receive(:password_in_history?).
          with(nil, 'bcd234').
          and_return(false)

        cut.
          should_receive(:prepare_password).
          with('bcd234', 'the_salt').
          and_return('{SSHA}the_password')

        cut.
          should_receive(:create_salt).
          with('joe').
          and_return('the_salt')

        cut.
          should_receive(:as_user).
          with('joe', 'abc123').
          and_yield(m_conn)

        cut.
          should_receive(:dn_from_login).
          with('joe').
          and_return('cn=joe,dc=com')

        expect(cut.change_password('joe', 'abc123', 'bcd234')).to eq(user_info)
      end

    end

  end

  context 'Private Methods' do

    context '#as_user' do

      it "should raise a BindError if the user was unable to bind to LDAP" do
        cut.should_receive(:dn_from_login).and_return('cn=joe,dc=com')

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com','abc123').
          and_raise(LDAP::Error)

        expect { cut.send(:as_user, 'joe', 'abc123') }.to raise_error(LdapBinder::BindError)
      end

      it "should yield to the block if the user successfully bound to LDAP" do
        cut.should_receive(:dn_from_login).and_return('cn=joe,dc=com')

        m_conn = double("LDAP::Connection")

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com','abc123').
          and_yield(m_conn)

        cut.send(:as_user, 'joe', 'abc123') { | conn | expect(conn).to eq(m_conn) }
      end

    end

    context '#perform_user_bind' do
      
      it "should raise a NoAuthStrategyFoundError if the criteria specified matches no strategy" do
        expect { cut.send(:perform_user_bind, {}, {}) }.to raise_error(LdapBinder::NoAuthStrategyFoundError)
      end

      it "should invoke the standard_bind strategy if a login and password criteria are specified" do
        cut.should_receive(:standard_bind).with({}, { login: 'joe', password: 'abc123' })
        
        cut.send(:perform_user_bind, {}, { login: 'joe', password: 'abc123' })
      end

      it "should invoke the sso_bind strategy if a token is specified" do
        cut.should_receive(:sso_bind).with({}, { token: 'abc123' })
        
        cut.send(:perform_user_bind, {}, { token: 'abc123' })
      end

      it "should raise a BindError if was an error doing a standard bind" do
        cut.
          should_receive(:standard_bind).
          with({}, { login: 'joe', password: 'abc123' }).
          and_raise(LDAP::Error)
        
        expect { cut.send(:perform_user_bind, {}, { login: 'joe', password: 'abc123' }) }.to raise_error(LdapBinder::BindError)
      end

      it "should raise a BindError if there was an error during an sso_bind" do
        cut.
          should_receive(:sso_bind).
          with({}, { token: 'abc123' }).
          and_raise(LDAP::Error)
        
        expect { cut.send(:perform_user_bind, {}, { token: 'abc123' }) }.to raise_error(LdapBinder::BindError)
      end

    end

    context '#standard_bind' do

      it "should simply bind with the password if no salt is present on the LDAP user" do
        m_conn = double("LDAP::Connection")

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'abc123').
          and_yield(m_conn)

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ] 
        }

        cut.send(:standard_bind, user_data, { login: 'joe', password: 'abc123' })
      end

      it "should raise an LDAP::Error exception if it fails to bind" do
        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'abc123').
          and_raise(LDAP::Error)

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ] 
        }

        expect { cut.send(:standard_bind, user_data, { login: 'joe', password: 'abc123' }) }.to raise_error(LDAP::Error)
      end

      it "should bind and convert the old password if there is salt in the user data" do
        criteria = { login: 'joe', password: 'abc123' }

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ],
          'destinationIndicator' => [ 'the_salt' ]
        }

        m_conn = double("LDAP::Connection")

        Digest::SHA1.
          should_receive(:hexdigest).
          with("--the_salt--abc123--").
          and_return('hashed_password')

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'hashed_password').
          and_yield(m_conn)

        cut.
          should_receive(:update_entry_to_new_password_type).
          with(m_conn, 'cn=joe,dc=com', 'abc123', 'the_salt')

        cut.send(:standard_bind, user_data, criteria)
      end

      it "should raise an LDAP:Error exception if the bind failed with the old salted password" do
        criteria = { login: 'joe', password: 'abc123' }

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ],
          'destinationIndicator' => [ 'the_salt' ]
        }

        Digest::SHA1.
          should_receive(:hexdigest).
          with("--the_salt--abc123--").
          and_return('hashed_password')

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'hashed_password').
          and_raise(LDAP::Error)

        cut.should_not_receive(:update_entry_to_new_password_type)

        expect { cut.send(:standard_bind, user_data, criteria) }.to raise_error(LDAP::Error)
      end

    end

    context '#sso_bind' do

      it "should bind using the dn and token" do
        criteria = { token: 'abc123' }

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ]
        }

        m_conn = double("LDAP::Connection")

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'abc123').
          and_yield(m_conn)

        cut.send(:sso_bind, user_data, criteria)
      end

      it "should raise an LDAP::Error exception on failure to bind" do
        criteria = { token: 'abc123' }

        user_data = {
          'dn' => [ 'cn=joe,dc=com' ]
        }

        cut.
          should_receive(:bind).
          with('cn=joe,dc=com', 'abc123').
          and_raise(LDAP::Error)

        expect { cut.send(:sso_bind, user_data, criteria) }.to raise_error(LDAP::Error)
      end

    end

    context '#update_entry_to_new_password_type' do

      it "should modify the user's password to the same clear text password salted with the original salt" do
        m_conn = double("LDAP::Connection")

        m_entry1 = double("LDAP::Entry")
        m_entry2 = double("LDAP::Entry")

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES, 'userPassword', [ '{SSHA1}hashed_password' ] ).
          and_return(m_entry1)

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'destinationIndicator', []).
          and_return(m_entry2)

        m_conn.
          should_receive(:modify).
          with('cn=joe,dc=com', [ m_entry1, m_entry2 ])

        cut.
          should_receive(:prepare_password).
          with('abc123', 'the_salt').
          and_return('{SSHA1}hashed_password')

        cut.send(:update_entry_to_new_password_type, m_conn, 'cn=joe,dc=com', 'abc123', 'the_salt')
      end

    end

    context '#password_in_history?' do

      it "should return false if no password history is specified" do
        expect(cut.send(:password_in_history?, nil, 'abc123')).to be_false
      end

      it "should return true if the password has appeared in the history" do
        history = [ 'Junk{SSHA}ababaababababaassssssssssssssssssssssssssssssssssssssss' ]
        Base64.
          should_receive(:decode64).
          with('ababaababababaassssssssssssssssssssssssssssssssssssssss').
          and_return('ssssssssssssssssssssssssssssssssssssssss')

        cut.
          should_receive(:prepare_password).
          with('abc123', 'ssssssssssssssssssssssssssssssssssssssss').
          and_return('{SSHA}ababaababababaassssssssssssssssssssssssssssssssssssssss')

        expect(cut.send(:password_in_history?, history, 'abc123')).to be_true
      end

      it "should return false if the password has not appeared in the history" do
        history = [ 'Junk{SSHA}ababaababababaassssssssssssssssssssssssssssssssssssssss' ]
        Base64.
          should_receive(:decode64).
          with('ababaababababaassssssssssssssssssssssssssssssssssssssss').
          and_return('ssssssssssssssssssssssssssssssssssssssss')

        cut.
          should_receive(:prepare_password).
          with('abc123', 'ssssssssssssssssssssssssssssssssssssssss').
          and_return('{SSHA}qbabaababababaassssssssssssssssssssssssssssssssssssssss')

        expect(cut.send(:password_in_history?, history, 'abc123')).to be_false
      end

    end

  end

end
