require_relative '../../../lib/certificate_wrapper/certificate_wrapper'

describe CertificateWrapper do
  context "#generate_certificate" do
    it "generates a certificate for ..." do
      CertificateWrapper.generate_certificate()
    end
  end
  context "#ecdsa_keygen" do
    it "generates the pair of keys [skey, pkey]" do
      expect(CertificateWrapper.ecdsa_keygen().size).to eq 2
    end
  end
end
