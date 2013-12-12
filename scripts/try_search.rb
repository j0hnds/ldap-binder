require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size != 2
login = ARGV.first
password = ARGV.last

# h = LdapBinder::Connection.conn.search(login: 'ckendall')

h = LdapBinder::Connection.conn.authenticate({ login: login,
                                               password: password })

puts h
