require_relative '../../../../lib/certificate_wrapper'

class Api::V1::UsersController < ApplicationController
  def login
    begin
      decrypted_params = asymmetric_decrypt params
      is_valid(decrypted_params[:token]) ? count = Integer(decrypted_params[:token][:count]) : raise("invalid token")
      is_count_valid(count) ? user = User.find(decrypted_params[:id]) : raise("invalid count (> 1024)")
      count > user.token_count ? user.token_count = count : raise("count (#{count}) < user.count (#{user.token_count})")
      if CryptoWrapper.verify(params[:token], params[:sig], user.pkey ) && user.save
        render json: {session_key: session_key}
      else
        user.destroy
        raise "user destroyed due to invalid request"
      end
    rescue Exception => e
      puts e.message
      head :bad_request
    end
  end

  def register
    begin
      nonce = User.find(params[:id]).nonce
      return head :bad_request unless CryptoWrapper.verify_hmac(params[:tag], params[:csr], nonce)
      # TODO
      render json: {certificate: "certificate"}
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
    #TODO
    params
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
