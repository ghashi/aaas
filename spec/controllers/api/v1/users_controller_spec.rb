require 'rails_helper'

RSpec.describe Api::V1::UsersController, :type => :controller do
  describe "POST #login" do
    context "when user is present in the list of current users" do
      let(:user) {FactoryGirl.create(:user)}
      let(:session_key){
        {session_key: "session_key"}
      }

      it "should return get request response" do
        allow(CryptoWrapper).to receive(:verify).and_return(true)
        post :login, id: user.id, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.body).to eq session_key.to_json
      end

      it "but verify returns false, then it should return bad request response" do
        allow(CryptoWrapper).to receive(:verify).and_return(false)
        post :login, id: user.id, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end

      it "but user count is lower than 12, then it should return bad request response" do
        fake_user = FactoryGirl.create(:user, token_count: 12)
        post :login, id: fake_user.id, token: {key: "1x1", timestamp: "11", count: "11", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end

      it "but user count is higher than 1024, then it should return bad request response" do
        fake_user = FactoryGirl.create(:user, token_count: 1025)
        post :login, id: fake_user.id, token: {key: "1x1", timestamp: "11", count: "1025", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end
    end

    context "when user is not present in the list of current users" do
      it "should return bad request response" do
        post :login, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end
    end
  end
end
