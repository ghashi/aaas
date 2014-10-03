require 'rails_helper'

RSpec.describe "users/new", :type => :view do
  before(:each) do
    assign(:user, User.new(
      :name => "MyString",
      :token_count => 1,
      :pkey => "MyString"
    ))
  end

  it "renders new user form" do
    render

    assert_select "form[action=?][method=?]", users_path, "post" do

      assert_select "input#user_name[name=?]", "user[name]"

      assert_select "input#user_token_count[name=?]", "user[token_count]"

      assert_select "input#user_pkey[name=?]", "user[pkey]"
    end
  end
end
