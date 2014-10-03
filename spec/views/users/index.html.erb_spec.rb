require 'rails_helper'

RSpec.describe "users/index", :type => :view do
  before(:each) do
    assign(:users, [
      User.create!(
        :name => "Name",
        :token_count => 1,
        :pkey => "Pkey"
      ),
      User.create!(
        :name => "Name",
        :token_count => 1,
        :pkey => "Pkey"
      )
    ])
  end

  it "renders a list of users" do
    render
    assert_select "tr>td", :text => "Name".to_s, :count => 2
    assert_select "tr>td", :text => 1.to_s, :count => 2
    assert_select "tr>td", :text => "Pkey".to_s, :count => 2
  end
end
