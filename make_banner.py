from PIL import Image, ImageDraw, ImageFont

# Create canvas
img = Image.new("RGB", (1200, 400), (10, 10, 20))
draw = ImageDraw.Draw(img)

# Title text
title = "DETCAP"
subtitle = "AI-Powered Cybersecurity Scanning Tool"
team = "The Commit Crew"

# Try default font (works on Windows)
font_title = ImageFont.load_default()
font_sub = ImageFont.load_default()

# Draw text
draw.text((500, 150), title, fill=(0, 255, 120), font=font_title)
draw.text((420, 200), subtitle, fill=(200, 200, 200), font=font_sub)
draw.text((520, 250), team, fill=(0, 180, 255), font=font_sub)

# Save banner
img.save("detcap_banner.png")

print("Banner created: detcap_banner.png")