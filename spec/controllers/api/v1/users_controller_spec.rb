require 'rails_helper'

RSpec.describe Api::V1::UsersController, :type => :controller do
  describe "POST #login" do
    context "when user is present in the list of current users" do
      let(:user) {FactoryGirl.create(:user)}
      let(:session_key){
        {session_key: "session_key"}
      }

      it "should return get request response" do
       # expect(requester).to receive(:get_response).with(URI.parse("http://en.wikipedia.org/wiki/Cassius_(band)")).and_return(request_response)
        post :login, id: user.id, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.body).to eq session_key.to_json
      end
    end
  end
end
