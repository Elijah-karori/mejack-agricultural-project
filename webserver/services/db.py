
import os
from supabase import create_client, Client

url: str = ""
print(url)
key: str = ""
print(key)
supabase: Client = create_client(url, key)
