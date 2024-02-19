
import os
from supabase import create_client, Client

url: str = "https://gjcexsnjvhpivxkejkcj.supabase.co"
print(url)
key: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdqY2V4c25qdmhwaXZ4a2Vqa2NqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMzEzNzUxOCwiZXhwIjoyMDE4NzEzNTE4fQ.sEq7QUI-1GuWrR76pHjLw_Bl_6RV7Qm48kuULkSJHgY"
print(key)
supabase: Client = create_client(url, key)
