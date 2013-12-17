require 'spec_helper'

class LdapBinder::TestManagerActions
  include LdapBinder::ManagerActions

end

describe LdapBinder::TestManagerActions do
  let(:cut) { LdapBinder::TestManagerActions.new }

  context 'Public Methods' do

    context '#user_search' do

      it "return the user's ldap attributes if bound and found" do
        search_criteria = { login: 'joe' }

        ldap_attrs = { 
          "dn"=>["cn=joe,ou=users,dc=com"], 
          "uid"=>["9c80c52c-cfce-4967-96ed-663348cf7c47"], 
          "createTimestamp"=>["20131211185617Z"], 
          "givenName"=>["Swiller"], 
          "sn"=>["Miller"], 
          "mail"=>["SwillerMiller@gmail.com"], 
          "description"=>["What a guy"], 
          "cn"=>["joe"]
        }

        m_ldap_attrs = double("LDAP::Entry")
        m_ldap_attrs.should_receive(:to_hash).and_return(ldap_attrs)

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:search).
          with("ou=users,dc=com",LDAP::LDAP_SCOPE_SUBTREE, '(cn=joe)', LdapBinder::ManagerActions::SEARCH_RETURN_ATTRS).
          and_yield(m_ldap_attrs)

        cut.stub(:as_manager).and_yield(m_conn)
        cut.stub(:user_root_dn).and_return("ou=users,dc=com")
        cut.stub(:ldap_user_search_criteria).with(search_criteria).and_return('(cn=joe)')

        expect(cut.user_search(search_criteria)).to eq(ldap_attrs)
      end

      it "should return nil if bound and not found" do
        search_criteria = { login: 'joe' }

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:search).
          with("ou=users,dc=com",LDAP::LDAP_SCOPE_SUBTREE, '(cn=joe)', LdapBinder::ManagerActions::SEARCH_RETURN_ATTRS)

        cut.stub(:as_manager).and_yield(m_conn)
        cut.stub(:user_root_dn).and_return("ou=users,dc=com")
        cut.stub(:ldap_user_search_criteria).with(search_criteria).and_return('(cn=joe)')

        expect(cut.user_search(search_criteria)).to be_nil
      end

      it "should raise and exception if manager can't be bound" do
        search_criteria = { login: 'joe' }

        # m_conn = double("LDAP::Connection")
        # m_conn.
        #   should_receive(:search).
        #   with("ou=users,dc=com",LDAP::LDAP_SCOPE_SUBTREE, '(cn=joe)', LdapBinder::ManagerActions::SEARCH_RETURN_ATTRS)

        cut.stub(:as_manager).and_raise(LDAP::Error)
        # cut.stub(:user_root_dn).and_return("ou=users,dc=com")
        # cut.stub(:ldap_user_search_criteria).with(search_criteria).and_return('(cn=joe)')

        expect { cut.user_search(search_criteria) }.to raise_error(LDAP::Error)
      end

    end

    context '#add_user' do

      it "should raise an exception if the user information has missing required attributes (last in this case)" do
        expect { cut.add_user({ login: 'joe', password: 'abc123' }) }.to raise_error(LdapBinder::MissingAttributeError)

        begin
          cut.add_user({ login: 'joe', password: 'abc123' })
        rescue LdapBinder::MissingAttributeError => ex
          expect(ex.missing_attributes).to eq([ :last ])
        end
      end


      it "should raise an exception if the manager is unable to bind" do
        cut.should_receive(:as_manager).and_raise(LdapBinder::BindError)

        expect { cut.add_user({ login: 'joe', password: 'abc123', last: 'Smith', uuid: 'aabbcc' }) }.to raise_error(LdapBinder::BindError)
      end

      it "should add a new user using the previous password and salt" do
        user_attributes = {
          login: 'joe',
          last: 'smith',
          password: 'abc123',
          first: 'Joseph',
          email: 'joe@gmail.com',
          note: 'A wonderful guy',
          salt: 'salty_snack',
          account_uid: 'account_1',
          application: 'brilliant_app'
        }

        m_entry = double("LDAP::Entries")

        m_conn = double("LDAP::Connection")
        m_conn.should_receive(:add).with('cn=joe,dc=com', m_entry)

        cut.should_receive(:as_manager).and_yield(m_conn)
        cut.should_receive(:dn_from_login).with('joe').and_return('cn=joe,dc=com')
        cut.should_receive(:create_unique_uuid).with(m_conn).and_return('unique_value')
        cut.should_not_receive(:prepare_password)
        cut.should_not_receive(:create_salt)
        cut.
          should_receive(:attribute_entries_for_add).
          with(user_attributes.merge(uuid: 'unique_value')).
          and_return(m_entry)

        expect(cut.add_user(user_attributes)).to eq(dn: 'cn=joe,dc=com', uuid: 'unique_value')

      end

      it "should add a new user creating a new password hash" do
        user_attributes = {
          login: 'joe',
          last: 'smith',
          password: 'abc123',
          first: 'Joseph',
          email: 'joe@gmail.com',
          note: 'A wonderful guy',
          account_uid: 'account_1',
          application: 'brilliant_app'
        }

        m_entry = double("LDAP::Entries")

        m_conn = double("LDAP::Connection")
        m_conn.should_receive(:add).with('cn=joe,dc=com', m_entry)

        cut.should_receive(:as_manager).and_yield(m_conn)
        cut.should_receive(:dn_from_login).with('joe').and_return('cn=joe,dc=com')
        cut.should_receive(:create_unique_uuid).with(m_conn).and_return('unique_value')
        cut.should_receive(:prepare_password).with('abc123', 'a salt').and_return('{SSHA1}hashed_password')
        cut.should_receive(:create_salt).with('joe').and_return('a salt')
        cut.
          should_receive(:attribute_entries_for_add).
          with(user_attributes.merge(password: '{SSHA1}hashed_password').merge(uuid: 'unique_value')).
          and_return(m_entry)

        expect(cut.add_user(user_attributes)).to eq(dn: 'cn=joe,dc=com', uuid: 'unique_value')

      end

    end

    context '#update_user' do

      it "should raise an exception if the manager is unable to bind" do
        cut.should_receive(:as_manager).and_raise(LdapBinder::BindError)

        expect { cut.add_user({ login: 'joe', password: 'abc123', last: 'Smith', uuid: 'aabbcc' }) }.to raise_error(LdapBinder::BindError)
      end

      it "should raise an exception if the user specified in the update attribute cannot be found in ldap" do
        user_attributes = { uuid: 'abc123' }

        cut.should_receive(:user_search).with(user_attributes).and_return(nil)

        expect { cut.update_user(user_attributes) }.to raise_error(LdapBinder::UserNotFoundError)
      end

      it "should update only normal attributes if no change to password or login" do
        user_attributes = { 
          uuid: 'abc123',
          login: 'joe',
          first: 'Joe',
          last: 'Smith',
          email: 'joe@gmail.com',
          note: 'A nice guy'
        }
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'uid' => [ 'unique_id' ],
          'cn' => [ 'joe' ]
        }

        m_conn = double("LDAP::Connection")
        m_conn.should_receive(:modify).with('cn=joe,dc=com', anything)

        cut.should_receive(:user_search).with(user_attributes).and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'givenName', :first)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'sn', :last)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'mail', :email)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'description', :note)

        expect(cut.update_user(user_attributes)).to eq(dn: 'cn=joe,dc=com', uuid: 'unique_id')
      end

      it "should update all normal attributes and the password if specified" do
        user_attributes = { 
          uuid: 'abc123',
          login: 'joe',
          first: 'Joe',
          last: 'Smith',
          email: 'joe@gmail.com',
          note: 'A nice guy',
          password: 'the_password'
        }
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'uid' => [ 'unique_id' ],
          'cn' => [ 'joe' ]
        }

        m_conn = double("LDAP::Connection")
        m_conn.should_receive(:modify).with('cn=joe,dc=com', anything)

        m_entry = double("LDAP::Entry")

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'userPassword', [ '{SSHA1}hashed_password' ]).
          and_return(m_entry)

        cut.should_receive(:user_search).with(user_attributes).and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        cut.
          should_receive(:prepare_password).
          with('the_password', 'the_salt').
          and_return('{SSHA1}hashed_password')
        cut.should_receive(:create_salt).with('joe').and_return('the_salt')
        
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'givenName', :first)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'sn', :last)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'mail', :email)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'description', :note)

        expect(cut.update_user(user_attributes)).to eq(dn: 'cn=joe,dc=com', uuid: 'unique_id')
      end

      it "should update normal attributes and should change the cn of the user if the login has changed" do
        user_attributes = { 
          uuid: 'abc123',
          login: 'joe',
          first: 'Joe',
          last: 'Smith',
          email: 'joe@gmail.com',
          note: 'A nice guy'
        }
        user_info = {
          'dn' => [ 'cn=jim,dc=com' ],
          'uid' => [ 'unique_id' ],
          'cn' => [ 'jim' ]
        }

        m_conn = double("LDAP::Connection")
        m_conn.should_receive(:modify).with('cn=jim,dc=com', anything)
        m_conn.
          should_receive(:modrdn).
          with('cn=jim,dc=com', 'cn=joe', true)

        cut.should_receive(:user_search).with(user_attributes).and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'givenName', :first)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'sn', :last)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'mail', :email)
        cut.should_receive(:update_entry).with(anything, user_info, user_attributes, 'description', :note)

        expect(cut.update_user(user_attributes)).to eq(dn: 'cn=joe,dc=com', uuid: 'unique_id')
      end

    end

    context '#delete_user' do

      it "should delete the user specified by 'dn' in the criteria" do
        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:delete).
          with('cn=joe,dc=com')

        cut.should_not_receive(:user_search)
        cut.should_receive(:as_manager).and_yield(m_conn)

        expect(cut.delete_user(dn: 'cn=joe,dc=com')).to eq('cn=joe,dc=com')
      end

      it "should delete the user found using other criteria" do
        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:delete).
          with('cn=joe,dc=com')

        cut.
          should_receive(:user_search).
          with(login: 'joe').
          and_return('dn' => [ 'cn=joe,dc=com' ])
        cut.should_receive(:as_manager).and_yield(m_conn)

        expect(cut.delete_user(login: 'joe')).to eq('cn=joe,dc=com')
      end

      it "should raise an UserNotFoundError if the user was not found to delete" do
        cut.
          should_receive(:user_search).
          with(login: 'biff').
          and_return(nil)

        expect { cut.delete_user(login: 'biff') }.to raise_error(LdapBinder::UserNotFoundError)
      end

    end

    context '#delete_all_users' do

      it "should remove all users from the user root in the DT" do
        m_entry1 = double("LDAP::Entry")
        m_entry1.stub(:dn).and_return('cn=user,ou=users,dc=com')

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:search).
          with("ou=users,dc=com", LDAP::LDAP_SCOPE_SUBTREE, '(objectClass=inetOrgPerson)', [ 'cn' ]).
          and_yield(m_entry1)
        m_conn.should_receive(:delete).with('cn=user,ou=users,dc=com')

        cut.should_receive(:as_manager).and_yield(m_conn)
        cut.stub(:user_root_dn).and_return("ou=users,dc=com")

        expect(cut.delete_all_users).to eq([ 'cn=user,ou=users,dc=com' ])
      end

    end

    context '#unlink_user' do
      
      it "should return nil if neither an application_uid or account_uid key is provided" do
        expect(cut.unlink_user('unique_id', {})).to be_nil
      end

      it "should raise an exception if the user was not found" do
        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(nil)

        expect { cut.unlink_user('unique_id', { account_uid: '1' }) }.to raise_error(LdapBinder::UserNotFoundError)
      end

      it "should do nothing if the user isn't associated with the specified application" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'businessCategory' => [ 'app2', 'app3' ]
        }
        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_not_receive(:as_manager)
        
        expect(cut.unlink_user('unique_id', application_uid: 'app1')).to eq('cn=joe,dc=com')
      end
      
      it "should update the user's businessCategory if the user is associated with the specified application" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'ou' => [ 'acct2', 'acct3' ],
          'businessCategory' => [ 'app2', 'app3' ]
        }

        m_entry1 = double("LDAP::Entry")
        m_entry2 = double("LDAP::Entry")
        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'ou', [ 'acct2', 'acct3' ]).
          and_return(m_entry1)

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'businessCategory', [ 'app3' ]).
          and_return(m_entry2)

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:modify).
          with('cn=joe,dc=com', [ m_entry1, m_entry2 ])

        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        expect(cut.unlink_user('unique_id', application_uid: 'app2')).to eq('cn=joe,dc=com')
      end

      it "should delete the user if the last application is unlinked" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'ou' => [ 'acct2', 'acct3' ],
          'businessCategory' => [ 'app2' ]
        }

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:delete).
          with('cn=joe,dc=com')

        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        expect(cut.unlink_user('unique_id', application_uid: 'app2')).to eq('cn=joe,dc=com')
      end
      
      it "should do nothing if the user isn't associated with the specified account" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'ou' => [ 'app2', 'app3' ]
        }
        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_not_receive(:as_manager)
        
        expect(cut.unlink_user('unique_id', account_uid: 'acct1')).to eq('cn=joe,dc=com')
      end
      
      it "should update the user's ou if the user is associated with the specified account" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'ou' => [ 'acct2', 'acct3' ],
          'businessCategory' => [ 'app2', 'app3' ]
        }

        m_entry1 = double("LDAP::Entry")
        m_entry2 = double("LDAP::Entry")
        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'ou', [ 'acct2' ]).
          and_return(m_entry1)

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'businessCategory', [ 'app2', 'app3' ]).
          and_return(m_entry2)

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:modify).
          with('cn=joe,dc=com', [ m_entry1, m_entry2 ])

        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        expect(cut.unlink_user('unique_id', account_uid: 'acct3')).to eq('cn=joe,dc=com')
      end
      
      it "should delete the user if the last account is unlinked" do
        user_info = {
          'dn' => [ 'cn=joe,dc=com' ],
          'ou' => [ 'acct3' ],
          'businessCategory' => [ 'app2', 'app3' ]
        }

        m_conn = double("LDAP::Connection")
        m_conn.
          should_receive(:delete).
          with('cn=joe,dc=com')

        cut.should_receive(:user_search).with(uuid: 'unique_id').and_return(user_info)
        cut.should_receive(:as_manager).and_yield(m_conn)
        
        expect(cut.unlink_user('unique_id', account_uid: 'acct3')).to eq('cn=joe,dc=com')
      end
      
    end

  end

  context 'Private Methods' do

    context '#uuid_exists?' do

      it "should return true if the uuid exists within the DT" do
        uuid = 'abc123'

        root_dn = "cn=bob,dc=users"

        m_conn = double("LDAP::Connection")
        m_conn.
          stub(:search).
          with(root_dn, LDAP::LDAP_SCOPE_SUBTREE, "(uid=#{uuid})", %w{ uid }).
          and_yield("entry")

        cut.stub(:user_root_dn).and_return(root_dn)

        expect(cut.send(:uuid_exists?, m_conn, uuid)).to be_true
      end

      it "should return false if the uuid does not exist within the DT" do
        uuid = 'abc123'

        root_dn = "cn=bob,dc=users"

        m_conn = double("LDAP::Connection")
        m_conn.
          stub(:search).
          with(root_dn, LDAP::LDAP_SCOPE_SUBTREE, "(uid=#{uuid})", %w{ uid })
        # No yield to the block; that means false....

        cut.stub(:user_root_dn).and_return(root_dn)

        expect(cut.send(:uuid_exists?, m_conn, uuid)).to be_false
      end

    end

    context '#create_uniqe_uuid' do

      it "should only create a single uuid if the initial one is not found in the DT" do
        m_conn = double("LDAP::Connection")

        cut.stub(:uuid_exists?).with(m_conn, 'abc123').and_return(false)
        SecureRandom.should_receive(:uuid).and_return('abc123')
        
        cut.send(:create_unique_uuid, m_conn)
      end

      it "should create as many uuid's as it takes if the initial one is found in the DT" do
        m_conn = double("LDAP::Connection")

        cut.stub(:uuid_exists?).with(m_conn, 'abc123').and_return(true)
        cut.stub(:uuid_exists?).with(m_conn, 'abc124').and_return(false)
        SecureRandom.should_receive(:uuid).and_return('abc123','abc124')
        
        cut.send(:create_unique_uuid, m_conn)
      end

    end

    context '#update_entry' do

      it "should do nothing if the existing attribute value is not being modified" do
        entry = []
        user_attrs = { note: 'The note' }
        ldap_attrs = { 'description' => [ 'The note' ] }

        LDAP.should_not_receive(:mod)

        cut.send(:update_entry, entry, ldap_attrs, user_attrs, 'description', :note)

        expect(entry).to be_empty
      end

      it "should do nothing if the optional attribute is not in the user info or in ldap" do
        entry = []
        user_attrs = {  }
        ldap_attrs = {  }

        LDAP.should_not_receive(:mod)

        cut.send(:update_entry, entry, ldap_attrs, user_attrs, 'description', :note)

        expect(entry).to be_empty
      end

      it "should modify the ldap attribute if the user value has changed" do
        entry = []
        user_attrs = { note: 'The note is different' }
        ldap_attrs = { 'description' => [ 'The note' ] }

        m_mod_entry = double("LDAP::ModEntry")

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_REPLACE, 'description', [ 'The note is different' ]).
          and_return(m_mod_entry)

        cut.send(:update_entry, entry, ldap_attrs, user_attrs, 'description', :note)

        expect(entry.size).to eq(1)
      end

      it "should add an attribute that is in the user but not in ldap" do
        entry = []
        user_attrs = { note: 'The note is different' }
        ldap_attrs = {  }

        m_mod_entry = double("LDAP::ModEntry")

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_ADD, 'description', [ 'The note is different' ]).
          and_return(m_mod_entry)

        cut.send(:update_entry, entry, ldap_attrs, user_attrs, 'description', :note)

        expect(entry.size).to eq(1)
      end

      it "should delete an attribute that is in ldap but not in the user" do
        entry = []
        user_attrs = {  }
        ldap_attrs = { 'description' => [ 'The note' ] }

        m_mod_entry = double("LDAP::ModEntry")

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_DELETE, 'description', [  ]).
          and_return(m_mod_entry)

        cut.send(:update_entry, entry, ldap_attrs, user_attrs, 'description', :note)

        expect(entry.size).to eq(1)
      end

    end

    context '#ldap_user_search_criteria' do

      it "should return a uid search filter if :uuid is in the search criteria" do
        search_criteria = { uuid: 'abc123', login: 'joe', account_uid: 'def321', token: 'aabbcc' }
        expect(cut.send(:ldap_user_search_criteria, search_criteria)).to eq("(uid=abc123)")
      end

      it "should return a login search filter if :login is in the search criteria, but not :uuid" do
        search_criteria = { login: 'joe', account_uid: 'def321', token: 'aabbcc' }
        expect(cut.send(:ldap_user_search_criteria, search_criteria)).to eq("(cn=joe)")
      end

      it "should return a token search filter if :token is in the search criteria, but not :uuid or :login or :account_uid" do
        search_criteria = { token: 'aabbcc' }
        expect(cut.send(:ldap_user_search_criteria, search_criteria)).to eq("(userPassword=aabbcc)")
      end

      it "should return an account_uid/token search filter if :token and :account_uid is in the search criteria, but not :uuid or :login " do
        search_criteria = { account_uid: 'def321', token: 'aabbcc' }
        expect(cut.send(:ldap_user_search_criteria, search_criteria)).to eq("(&(userPassword=aabbcc)(businessCategory=def321))")
      end

      it "should raise an exception if no valid criteria is found" do
        search_criteria = {  }
        expect { cut.send(:ldap_user_search_criteria, search_criteria) }.to raise_error
      end

    end

    context '#as_manager' do

      it "on successful bind, it should pass the bound connection to the block" do
        called = false
        m_conn = double("LDAP::Connection")

        cut.
          stub(:current_configuration).
          and_return({ 'manager-dn' => "cn=Manager,dc=com", 'manager-pw' => 'test1234' })

        cut.
          should_receive(:bind).
          with("cn=Manager,dc=com", 'test1234').
          and_yield(m_conn)

        cut.send(:as_manager) { | conn | expect(conn).to(eq(m_conn)); called = true }
        expect(called).to be_true
      end

      it "on failed bind, it should raise an exception and not call the block" do
        called = false
        m_conn = double("LDAP::Connection")

        cut.
          stub(:current_configuration).
          and_return({ 'manager-dn' => "cn=Manager,dc=com", 'manager-pw' => 'test1234' })

        cut.
          should_receive(:bind).
          with("cn=Manager,dc=com", 'test1234').
          and_raise(LDAP::Error)

        expect { cut.send(:as_manager) { | conn | expect(conn).to(eq(m_conn)); called = true } }.to raise_error(LdapBinder::BindError)
        expect(called).to be_false
      end

    end

    context '#missing_required_attributes' do

      it "should return all required attributes if no attributes are specified" do
        expect(cut.send(:missing_required_attributes, {})).to eq([ :login, :last, :password ])
      end

      it "should return the missing required attribute if all but one of the required attributes is specified" do
        expect(cut.send(:missing_required_attributes, { login: 'joe', uuid: 'abc123', password: 'password' })).to eq([ :last ])
      end

      it "should return an empty arrayif all the required attributes are specified" do
        expect(cut.send(:missing_required_attributes, { login: 'joe', last: 'smith', uuid: 'abc123', password: 'password' })).to eq([])
      end

    end

    context '#attributes_sufficient?' do

      it "should return false if no attributes are specified" do
        expect(cut.send(:attributes_sufficient?, {})).to be_false
      end

      it "should return false if all but one of the required attributes is specified" do
        expect(cut.send(:attributes_sufficient?, { login: 'joe', uuid: 'abc123', password: 'password' })).to be_false
      end

      it "should return if all the required attributes are specified" do
        expect(cut.send(:attributes_sufficient?, { login: 'joe', last: 'smith', uuid: 'abc123', password: 'password' })).to be_true
      end

    end

    context '#non_empty_attributes' do

      it "should return an empty hash if the user attribute hash is empty" do
        expect(cut.send(:non_empty_attributes, {})).to eq({})
      end

      it "should return an empty hash if the user attribute values are all empty" do
        expect(cut.send(:non_empty_attributes, { k1: nil, k2: '' })).to eq({})
      end

      it "should return all attributes if none are empty" do
        expect(cut.send(:non_empty_attributes, { k1: 1, k2: '2' })).to eq({ k1: 1, k2: '2' })
      end

      it "should return only the non-empty attributes" do
        expect(cut.send(:non_empty_attributes, { k1: nil, k2: '2' })).to eq({ k2: '2' })
      end

    end

    context '#attribute_entries_for_add' do

      it "should create an entry for all valie non-empty attributes" do
        user_attributes = { login: 'joe', invalid: 'something', empty: '', last: 'smith' }

        m_entry1 = double("LDAP::Entry")
        m_entry2 = double("LDAP::Entry")
        m_entry3 = double("LDAP::Entry")
        
        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_ADD, 'objectClass', [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ]).
          and_return(m_entry1)

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_ADD, 'cn', [ 'joe' ]).
          and_return(m_entry2)

        LDAP.
          should_receive(:mod).
          with(LDAP::LDAP_MOD_ADD, 'sn', [ 'smith' ]).
          and_return(m_entry3)

        entry = cut.send(:attribute_entries_for_add, user_attributes)

        expect(entry).to eq([ m_entry1, m_entry2, m_entry3 ])
      end

    end

  end

end
