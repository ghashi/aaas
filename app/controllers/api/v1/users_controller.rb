require_relative '../../../../lib/certificate_wrapper'
require_relative '../../../../lib/certificate_wrapper/certificate_wrapper'
require_relative '../../../../lib/crypto_wrapper/crypto_wrapper.so'

class Api::V1::UsersController < ApplicationController
  skip_before_filter  :verify_authenticity_token

  def login
    begin
      decrypted_token = asymmetric_decrypt params
      raise("id from request is different from id from token") if params[:id] != decrypted_token["id"]
      is_valid(decrypted_token) ? count = Integer(decrypted_token["count"]) : raise("invalid token")
      is_count_valid(count) ? user = User.find(params[:id]) : raise("invalid count (> 1024)")
      count > user.token_count ? user.token_count = count : raise("count (#{count}) < user.count (#{user.token_count})")
      if CryptoWrapper.verify(params[:token], params[:sig], user.pkey ) && user.save
        render json: {"session_key" => decrypted_token["session_key"], "cname" => user.name}
      else
        #user.destroy
        raise "user destroyed due to invalid request"
      end
    rescue Exception => e
      logger.error e.message
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
    decrypted_val = ::CertificateWrapper.ntru_decrypt(CertificateWrapper.ntru_skey, params[:token])
    decoded_val = ActiveSupport::JSON.decode decrypted_val
    logger.debug "Api::V1::UsersController.asymmetric_decrypt decrypted_val=#{decrypted_val} decoded_val=#{decoded_val}"
    decoded_val
  end

  def certificate_of(csr)
    ::CertificateWrapper.generate_certificate(csr, CertificateWrapper.valid, CertificateWrapper.ca_skey)
  end

  def is_valid(token)
    token.has_key?("session_key") && token.has_key?("count") && token.has_key?("id")
  end

  def is_count_valid(count)
    count < 2**10
  end
end
