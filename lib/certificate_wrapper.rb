class CertificateWrapper
  def self.ca_skey
    @ca_skey ||= GetKeys.call[0]
  end

  def self.valid
    @valid ||= (Time.now + ::Rails.application.secrets[:certificate_duration]).strftime("%G%m%d%H%M%S")
  end
end
