#!/usr/bin/env ruby
$: << "../lib"
require 'ldap-binder'

all_uuids = []

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
all_uuids << result[:uuid]
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
all_uuids << result[:uuid]
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
all_uuids << result[:uuid]
glorias_uuid = result[:uuid]
puts result.inspect

puts "Adding 'julio' user..."
user_info = {
  login: 'julio',
  last: 'Gonzales',
  password: '2b86935982d6f79ad2b99d519bd00ea987e6c2bb',
  salt: '123fe24c097387f4dd58a90ab767bf403b0d0666',
  first: 'Julio',
  email: 'julio@gmail.com',
  note: 'From run_all script',
  account_uid: 'account_1',
  application_uid: 'abaqis'
}
result = LdapBinder::Connection.mgr.add_user user_info
all_uuids << result[:uuid]
julio_uuid = result[:uuid]
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

# Create a link to application and account to user
puts "Linking user..."
result = LdapBinder::Connection.mgr.link_user({ login: 'joe' }, { application_uid: 'EmpSat', account_uid: 'account_6' })
puts result.inspect
puts 'done.'

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

# Can we authenticate as julio? (custom password)
puts "Authenticating julio"
result = LdapBinder::Connection.mgr.authenticate login: 'julio', password: 'Broncos2014'
puts result.inspect
puts "done"

# Can joe change his password
puts "Changing Joe's password..."
result = LdapBinder::Connection.mgr.change_password 'joe', 'Broncos2014', 'Sandy2012'
puts result.inspect
puts "done."

# Return all users with uuids
puts "Returning all users by uuid"
result = LdapBinder::Connection.mgr.all_uuids(all_uuids)
puts result.inspect

# Is the email available?
puts "Checking for email availability..."
# First, with a uuid
result = LdapBinder::Connection.mgr.unique_attribute_available?(julio_uuid, 'mail', 'julio@gmail.com')
puts result
# Now, without a uuid
result = LdapBinder::Connection.mgr.unique_attribute_available?(nil, 'mail', 'julio@gmail.com')
puts result
