class CertificateWrapper
  def self.ca_skey
    @ca_skey ||= GetKeys.call[0].chomp
  end

  def self.ca_pkey
    @ca_skey ||= GetKeys.call[1].chomp
  end

  def self.ntru_skey
    @ntru_skey ||= GetKeys.call[2].chomp
  end

  def self.ntru_pkey
    @ntru_pkey ||= GetKeys.call[3].chomp
  end

  def self.valid
    @valid ||= (Time.now + ::Rails.application.secrets[:certificate_duration]).strftime("%G%m%d%H%M%S")
  end
end
