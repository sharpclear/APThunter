import fasttext
import fasttext.util

src = "./app/models/fasttext/cc.en.300.bin"
dst = "./app/models/fasttext/cc.en.100.bin"

ft = fasttext.load_model(src)
print("before:", ft.get_dimension())  # 300

fasttext.util.reduce_model(ft, 100)
print("after:", ft.get_dimension())   # 100

ft.save_model(dst)
print("saved to:", dst)