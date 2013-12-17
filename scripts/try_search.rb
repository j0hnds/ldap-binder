#!/usr/bin/env ruby

$: << "../lib"
require 'ldap-binder'

raise "Must specify user name and password!!!" if ARGV.size != 2
login = ARGV.first
password = ARGV.last

h = LdapBinder::Connection.mgr.authenticate({ login: login,
                                               password: password })

raise "User #{login} cannot be authenticated!" if h.nil?
puts h
