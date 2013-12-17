module LdapBinder

  module CryptoSupport

    #
    # Prepares a password for use with LDAP
    #
    def prepare_password(password, salt=create_salt)
      pwdigest = Digest::SHA1.digest("#{password}#{salt}")
      "{SSHA}" + Base64.encode64("#{pwdigest}#{salt}").chomp!.tap { | s | puts "HASH = #{s}" }
    end

    #
    # Creates a salt to use for better hashing of a password
    #
    def create_salt(login='default_login')
      Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{login}--")
    end

  end

end
