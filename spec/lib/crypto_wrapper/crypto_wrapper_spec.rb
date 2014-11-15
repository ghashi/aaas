require_relative '../../../lib/crypto_wrapper/crypto_wrapper'

describe CryptoWrapper do
  context "#verify" do
    it "receive message, signature and pkey, then validate them" do
      # Long Johnson, Don Piano
      message = "TG9uZyBKb2huc29uLCBEb24gUGlhbm8="
      signature = "AAAA16Y7jsXfMf0wb3ErnHsPswABAHZf25PB9xMhAZt6xq+l3YEBAQDwOHH+Yb/Yq1k82AkaOlH1AgEAAl9Pyaq41Lg+uKevAlDDdQMBAMrxqBLW8zjxn2RLbN5PjgEEAQCuL8rPjdh2CUR5yvOeAyK2BQEAskYi/q/3S5TXS4AEqQBUZwYBAMKy5H455p+Fv+tYwIse5vMHAQBvZTrlg6YkjDE0DxvIfY+lCAEAtllE3cNvzI0NcnzZJ6g4QwkBAOb9JYb/Co5sSP5L/8t8Rip6tFPHHJ4p+sTlkom+FOXCxipPuchtf7uKbvYP+4PmPTp8nimC5fWXkzTBT8p5DJrUtxr8M/tRJB95v47ZYvGIvEcRl0VRJy1MaAZP0r61SgUTH4CGc+zENhhmmCawtfPzInqlHFoe9n0uUiL9oGLYptOo4sKkFVMSMrO8cg4LduBnA0EhQWL9QAKpCSf2/YESfmQ77hbI/cLs5h+FC0vntD3KN7rgiZtMs57pXCwdUZdMreXA/tCa2azSAYY6HiJ9sIEZ6motMNfpdjnjbqY+eHIjOURRYlRkPSSqAPMt2XSEw6BvxSmhofvZCaflyUGx0koljKcZuyJIGXxVv8ltnWp3lV5Jgx4v8hE9xee2yjNnP0JSXYWiiDFcXQpxGESSPSd4MZsBgXlMNQBA07JB9Jm2/EF7U3AA5eQEZ588sx61ViWwr4gkChFxSiMthgelgeACGibspYy9EqNfVHAMpdeW9wq2pm3tQLj9ptqwkzOneDoA0qUS9QNrxZnYxM+d3wszVb1zcYz+9nDg3xm7bRzU0rhkiv6aoqy2oJomICFECrOjHwkuUiQlp4YJY2RW86RPoqqhZt1f7txJ8q3zQECBWhx1a9OYZJg3ZDbgGrHsskViWCcBzXDdjeLzEHAgUQkFvqT/Ba45ZvG7z3H4dvNi4UFcLHkJFwrhR1PgQ3cDkoYBdg+q3gr2YiOa7yu72Q/9XCtadqcxhMBWk2oer++z1URtvxXkjCIomsvQ7vDPpQALFnFISDoFFsxpEhlyQq4sb3Q0IyXTiyRqsNqLeGp9jfOCHeiHQEv3jHXwvzkfunfT8NaDwZ0f2SIhcq8rpMslwALRkoUalTXuSB+OWRRP8l7zWGh0efQrZv9rZWy7vg5W6wx0UdzJkRhe3IMIKMkiNU7kXHpejcD5jEb6wGpR13FDq1Kd4hUp36ldHyOU+jAgfhuVPgZF1Cti1+Fm9yBGhua3dXv/ZQMOxI3shJ95bdDFQDJZFRzQzg1PgaiB3PqY6CvrRnl4qQkc3NUlLqrm1iPl/h+s4cKaHgYlPaygQe0U433DYjeoAaeqcQO6taqKaD7rLukcZLCE1VerohyRDoQjhAeDTwMdbSuVCmfP2Qm1nbPXWbu3xVxhLV+MUtX5AGyLTdPTlaFQfatekykYE2jqF9dlfJ0vRQd4IayRp2Uydw5y472eIC6BhNUxZS74ljyO/8DTGgA74/Jd5MPple/Z/AFWM6Tj+KzVUH98beQPsWjRO58xQOo0wjOO/kUvTivbCLIe21/olfy3nIluxX2MrW4GiVT8qQ6OMzbuenXt0T7LOwnUkdlL++tr5+XPp7c7safwWBSPB854KEAp/W2e39hr4qVUO6WfRQJCLoqoY0vDkKt5H5CfvfdHws9sIUJ1u67lSnhT4ZyrFbhjgvs6Rf4UE/rf3ezuzG1ekLLCDo+HjjaBebuFeg=="
      pkey = "hgmOJcOnjrlE5dhVmn7PKA=="
      expect(CryptoWrapper.verify(message, signature, pkey)).to eq true
    end
  end
end