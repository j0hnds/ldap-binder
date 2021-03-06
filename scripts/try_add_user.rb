#!/usr/bin/env ruby
$: << "../lib"
require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size != 2
login = ARGV.first
password = ARGV.last

user_info = {
  login: login,
  first: "John",
  last: "Doe",
  password: password,
  email: "mail@gmail.com",
  note: "He/she is a very nice guy/gal",
  account_uid: 'abc123',
  application: 'abaqis' }

new_user = LdapBinder::Connection.mgr.add_user(user_info)

puts new_user.inspect
