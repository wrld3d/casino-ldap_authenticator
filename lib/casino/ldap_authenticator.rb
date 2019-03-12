require 'net/ldap'
require 'casino/authenticator'

class CASino::LDAPAuthenticator
  DEFAULT_USERNAME_ATTRIBUTE = 'uid'

  # @param [Hash] options
  def initialize(options)
    @options = options
    @first_name_attribute = options[:first_name_attribute] || :givenName
    @email_attribute = options[:email_attribute] || :mail
  end

  def validate(username, password)
    authenticate(username, password)
  rescue Net::LDAP::LdapError => e
    raise CASino::Authenticator::AuthenticatorError,
      "LDAP authentication failed with '#{e}'. Check your authenticator configuration."
  end

  def update_password(username, password)
    ldap_update_password(username, password)
  rescue Net::LDAP::LdapError => e
    raise CASino::Authenticator::AuthenticatorError,
      "LDAP change password failed with '#{e}'. Check your authenticator configuration."
  end

  def load_user_data(username)
    ldap = connect_to_ldap
    user = ldap_user(username, ldap, false)
    return false unless user

    user_data(user)
  end

  def first_name_from_extra_attributes(extra_attributes)
    extra_attributes[@first_name_attribute]
  end

  def email_from_extra_attributes(extra_attributes)
    extra_attributes[@email_attribute]
  end

  private

  def connect_to_ldap
    Net::LDAP.new.tap do |ldap|
      ldap.host = @options[:host]
      ldap.port = @options[:port]
      ldap.base = @options[:base]
      if @options[:encryption]
        ldap.encryption(@options[:encryption].to_sym)
      end
      unless @options[:admin_user].nil?
        ldap.auth(@options[:admin_user], @options[:admin_password])
      end
    end
  end

  def authenticate(username, password)
    # Don't allow "Unauthenticated bind" (http://www.openldap.org/doc/admin24/security.html#Authentication%20Methods)
    return false unless password && !password.empty?

    ldap = connect_to_ldap
    user = ldap.bind_as(:base => @options[:base], :size => 1, :password => password, :filter => user_filter(username, false))
    if user
      user_data(ldap_user(username, ldap, false))
    else
      false
    end
  end

  def ldap_update_password(username, password)
    return false if password.blank?

    ldap = connect_to_ldap
    user = ldap_user(username, ldap, true)
    return false unless user

    ldap.replace_attribute user.dn, :userPassword, encrypt_password(password)
  end

  def ldap_user(username, ldap, real_username)
    include_attributes = @options[:extra_attributes].values + [username_attribute]
    user = ldap.search(:base => @options[:base], :filter => user_filter(username, real_username), :attributes => include_attributes)
    return nil if user.nil?
    if user.is_a?(Array)
      user = user.first
    end
  end

  def user_data(user)
    attributes = extra_attributes(user)
    {
      username: user[real_username_attribute].first,
      extra_attributes: attributes
    }
  end

  def username_attribute
    @options[:username_attribute] || DEFAULT_USERNAME_ATTRIBUTE
  end

  def real_username_attribute
    @options[:real_username_attribute].presence || username_attribute
  end

  def user_filter(username, real_username)
    filter = Net::LDAP::Filter.eq(real_username ? real_username_attribute : username_attribute, username)
    unless @options[:filter].nil?
      filter &= Net::LDAP::Filter.construct(@options[:filter])
    end
    filter
  end

  def extra_attributes(user)
    if @options[:extra_attributes]
      result = {}
      @options[:extra_attributes].each do |index_result, index_ldap|
        value = user[index_ldap]
        if value
          result[index_result] = "#{value.first}"
        end
      end
      result
    else
      nil
    end
  end

  def encrypt_password(password)
    Net::LDAP::Password.generate(password_encryption_method, password)
  end

  def password_encryption_method
    @password_encryption_method ||= @options.fetch(:password_encryption_method, :ssha).to_sym
  end
end
