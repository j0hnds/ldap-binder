#!/usr/bin/env ruby

$: << "../lib"
require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size < 2
login = ARGV[0]
password = ARGV[1]
new_password = ARGV[2]

# Need to get the UUID - that's how we're going to do the search
u = LdapBinder::Connection.mgr.user_search(login: login)

raise "Unable to find user: #{login}" if u.nil?

user_attributes = {
  uuid: u['uid'].first,
  login: "#{login}_a",
  first: 'Swiller',
  last: 'Miller',
  email: 'SwillerMiller@gmail.com',
  # note: 'What a guy'
}

user_attributes[:password] = new_password unless new_password.nil?
  
LdapBinder::Connection.mgr.update_user(user_attributes)

