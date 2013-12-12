require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size != 3
login = ARGV[0]
old_password = ARGV[1]
new_password = ARGV[2]

LdapBinder::Connection.conn.change_password(login, old_password, new_password)

