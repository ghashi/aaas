require_relative '../../../../lib/certificate_wrapper'
require_relative '../../../../lib/certificate_wrapper/certificate_wrapper'
require_relative '../../../../lib/crypto_wrapper/crypto_wrapper.so'

class Api::V1::UsersController < ApplicationController
  skip_before_filter  :verify_authenticity_token

  def login
    begin
      decrypted_token = asymmetric_decrypt params
      # TODO arrumar token e apagar "count = 1"
      #is_valid(decrypted_params[:token]) ? count = Integer(decrypted_params[:token][:count]) : raise("invalid token")
      count = 1
      p "id: " + params[:id]
      is_count_valid(count) ? user = User.find(params[:id]) : raise("invalid count (> 1024)")
      count > user.token_count ? user.token_count = count : raise("count (#{count}) < user.count (#{user.token_count})")
      p params[:sig]
      p params[:token]
      p user.pkey
      p CryptoWrapper.verify(params[:token], params[:sig], user.pkey )
      if CryptoWrapper.verify(params[:token], params[:sig], user.pkey ) && user.save
        p "hahahah"
        render json: {session_key: session_key}
      else
        p "destroy:e  "
        #user.destroy
        raise "user destroyed due to invalid request"
      end
    rescue Exception => e
      puts e.message
      head :bad_request
    end
  end

  def register
    begin
      user = User.find(params[:id])
      nonce = user.nonce
      return head :bad_request unless ::CryptoWrapper.verify_hmac(params[:tag], params[:csr], nonce)
      user.pkey = ::CertificateWrapper.get_csr_pkey(params[:csr])
      if user.save
        render json: {certificate: certificate_of(params[:csr])}
      else
        head :bad_request
      end
    rescue Exception => e
      puts e.message
      head :bad_request
    end
  end

  def ecdsa_pkey
    render text: CertificateWrapper.ca_pkey
  end

  def ntru_pkey
    render text: CertificateWrapper.ntru_pkey
  end

  private

  def asymmetric_decrypt(params)
      p ::CertificateWrapper.ntru_decrypt(CertificateWrapper.ntru_skey, params[:token])
  end

  def certificate_of(csr)
    ::CertificateWrapper.generate_certificate(csr, CertificateWrapper.valid, CertificateWrapper.ca_skey)
  end

  def is_valid(token)
    token.has_key?("key") && token.has_key?("timestamp") &&
      token.has_key?("count") && token.has_key?("index")
  end

  def session_key
    # TODO
    "session_key"
  end

  def is_count_valid(count)
    count < 2**10
  end
end
