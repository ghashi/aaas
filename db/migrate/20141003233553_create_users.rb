class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :name
      t.integer :token_count
      t.string :pkey

      t.timestamps
    end
  end
end
