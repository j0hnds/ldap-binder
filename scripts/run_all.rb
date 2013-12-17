#!/usr/bin/env ruby
$: << "../lib"
require 'ldap-binder'

# Clean everything up; pretty dangerous command...
puts "Deleting all users..."
LdapBinder::Connection.mgr.delete_all_users
puts "done."

# Add three users
puts "Adding 'joe' user..."
user_info = {
  login: 'joe',
  last: 'Smith',
  password: 'Broncos2014',
  first: 'Joe',
  email: 'joe@gmail.com',
  note: 'From run_all script',
  account_uid: 'account_2',
  application_uid: 'abaqis'
}
result = LdapBinder::Connection.mgr.add_user user_info
puts result.inspect

puts "Adding 'harriet' user..."
user_info = {
  login: 'harriet',
  last: 'Smith',
  password: 'Broncos2014',
  first: 'Harriet',
  email: 'harriet@gmail.com',
  note: 'From run_all script',
  account_uid: 'account_2',
  application_uid: 'abaqis'
}
result = LdapBinder::Connection.mgr.add_user user_info
puts result.inspect

puts "Adding 'gloria' user..."
user_info = {
  login: 'gloria',
  last: 'Smith',
  password: 'Broncos2014',
  first: 'Gloria',
  email: 'gloria@gmail.com',
  note: 'From run_all script',
  account_uid: 'account_2',
  application_uid: 'abaqis'
}
result = LdapBinder::Connection.mgr.add_user user_info
glorias_uuid = result[:uuid]
puts result.inspect

puts "done."

# Can we find the user we just added?
puts "Searching for user..."
result = LdapBinder::Connection.mgr.user_search login: 'joe'
puts result.inspect
puts "done."

# Can we update the user we just added?
puts "Updating user..."
result = LdapBinder::Connection.mgr.update_user login: 'joe', last: 'Einstein'
puts result.inspect
puts "done."

# Can we unlink gloria?
puts "Unlinking gloria..."
result = LdapBinder::Connection.mgr.unlink_user glorias_uuid, account_uid: 'account_2'
puts result.inspect
puts "done."

# Can we delete harriet?
puts "Deleting harriet..."
result = LdapBinder::Connection.mgr.delete_user login: 'harriet'
puts result.inspect
puts "done."

# Can we authenticate as joe?
puts "Authenticating joe"
result = LdapBinder::Connection.mgr.authenticate login: 'joe', password: 'Broncos2014'
puts result.inspect
puts "done"

# Can joe change his password
puts "Changing Joe's password..."
result = LdapBinder::Connection.mgr.change_password 'joe', 'Broncos2014', 'Sandy2012'
puts result.inspect
puts "done."