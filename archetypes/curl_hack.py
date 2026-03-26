import requests
from bs4 import BeautifulSoup


def fix_encoding(text):
    try:
        return text.encode('latin1').decode('utf-8')
    except:
        return text


url = "https://hackropole.fr/en/crypto/"
res = requests.get(url)
soup = BeautifulSoup(res.text, "html.parser")

rows = soup.find_all("tr", attrs={"data-challenge": True})


html = []
html.append('<table border="1" cellpadding="6" cellspacing="0">')
html.append("""
<tr>
  <th>Chall</th>
  <th>Diff</th>
  <th>Solved</th>
  <th>Link</th>
</tr>
""")

for row in rows:
    cols = row.find_all("td")
    
    name = fix_encoding(cols[1].get_text(strip=True))
    dif1 = cols[2].get_text(strip=True)
    diff = 0
    if dif1 == "intro":
        diff = 1
    elif dif1 == "star":
        diff = 2
    elif dif1 == "starstar":
        diff = 3
    elif dif1 == "starstarstar":
        diff = 4

    html.append(f"""
<tr>
  <td>{name}</td>
  <td>{diff}</td>
  <td>\u274C</td>
  <td></td>
</tr>
""")

html.append("</table>")

# output final
result = "\n".join(html)

print(result)