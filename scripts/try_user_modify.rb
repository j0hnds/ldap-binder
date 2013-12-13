$: << '../lib'
require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size < 2
login = ARGV[0]
password = ARGV[1]
new_password = ARGV[2]

# Need to get the UUID - that's how we're going to do the search
u = LdapBinder::Connection.conn.search(login: login)

# h = LdapBinder::Connection.conn.search(login: 'ckendall')

user_attributes = {
  uuid: u['uid'].first,
  login: "#{login}_a",
  first: 'Swiller',
  last: 'Miller',
  email: 'SwillerMiller@gmail.com',
  note: 'What a guy'
}

user_attributes[:password] = new_password unless new_password.nil?
  
LdapBinder::Connection.conn.update_user(user_attributes)

