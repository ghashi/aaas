require 'rails_helper'
require_relative '../../../lib/mss/mss_wrapper'

describe MssWrapper do
  context "#verify" do
    it "receive message, signature and key, then validate them" do
      # Ola Cassius
      message = "T2xhIENhc3NpdXMK"
      #14
      signature = "MTQK"
      # 01
      key = "MDEK"
      expect(MssWrapper.verify(message, signature, key)).to eq true
    end
  end
end
