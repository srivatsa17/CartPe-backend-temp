from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives

def send_email(subject, to, template, domain, uid, token):
    try: 
        from_email = 'vatsaecommerce@gmail.com'
        html_content = render_to_string(
                        template, 
                        {
                            'domain': domain,
                            'uid': uid,
                            'token': token
                        }
                    )
        text_content = strip_tags(html_content) 

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        response = {
            "message": "Sent email successfully",
            "status": 200
        }

    except Exception:
        response = {
            "message": "Unable to send email",
            "status": 400
        }
        
    return response