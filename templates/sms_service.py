import requests
import json

class SMSOTP:
    def __init__(self):
        # Configure with your SMS provider (Twilio, Nexmo, etc.)
        self.provider = "twilio"  # or 'nexmo', 'aws_sns'
        self.api_key = "your-api-key"
        self.api_secret = "your-api-secret"
        self.from_number = "+1234567890"
    
    def send_otp(self, phone_number, otp):
        """Send OTP via SMS"""
        if self.provider == "twilio":
            return self.send_twilio_sms(phone_number, otp)
        elif self.provider == "nexmo":
            return self.send_nexmo_sms(phone_number, otp)
        else:
            print(f"SMS to {phone_number}: Your OTP is {otp}")
            return True
    
    def send_twilio_sms(self, phone_number, otp):
        """Send SMS using Twilio"""
        try:
            from twilio.rest import Client
            client = Client(self.api_key, self.api_secret)
            message = client.messages.create(
                body=f"Your Network Scanner verification code is: {otp}. Valid for 10 minutes.",
                from_=self.from_number,
                to=phone_number
            )
            return True
        except Exception as e:
            print(f"Twilio error: {e}")
            return False
    
    def send_nexmo_sms(self, phone_number, otp):
        """Send SMS using Nexmo/Vonage"""
        try:
            url = "https://rest.nexmo.com/sms/json"
            data = {
                'api_key': self.api_key,
                'api_secret': self.api_secret,
                'from': self.from_number,
                'to': phone_number,
                'text': f"Your Network Scanner verification code is: {otp}"
            }
            response = requests.post(url, data=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Nexmo error: {e}")
            return False