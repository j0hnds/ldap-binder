module LdapBinder

  class MissingAttributeError < StandardError

    attr_reader :missing_attributes

    def initialize(missing_attributes)
      @missing_attributes = missing_attributes
    end

  end

  class BindError < StandardError

    attr_reader :inner_exception, :user_data

    def initialize(user_data=nil, inner_exception=nil)
      @user_data = user_data
      @inner_exception = inner_exception
    end

  end

  class UserNotFoundError < StandardError

    attr_reader :user_criteria

    def initialize(user_criteria)
      @user_criteria = user_criteria
    end

  end

  class NoAuthStrategyFoundError < StandardError

    attr_reader :user_criteria

    def initialize(user_criteria)
      @user_criteria = user_criteria
    end

  end

  class PasswordHistoryError < StandardError

  end

end
