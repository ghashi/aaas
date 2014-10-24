class Api::V1::UsersController < ApplicationController
  def login
    begin
      decrypted_params = decrypt params
      if is_valid decrypted_params[:token]
        count = Integer(decrypted_params[:token][:count])
        if is_count_valid(count)
          user = User.find decrypted_params[:id]
          if count > user.token_count
            user.token_count = count
            if CryptoWrapper.verify(params[:token], params[:sig], user.pkey ) && user.save
              render json: {session_key: session_key}
            else
              user.destroy
              head :bad_request
            end
          else
            p "invalid count(> #{user.token_count})"
            head :bad_request
          end
        else
          p "invalid count (> 1023)"
        end
      else
        p "invalid token"
        head :bad_request
      end
    rescue Exception => e
      puts e.message
      head :bad_request
    end
  end

  private

  def decrypt(params)
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
