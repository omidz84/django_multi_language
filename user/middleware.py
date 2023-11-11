from django.utils.translation import activate


class LanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            request.LANGUAGE_CODE = request.headers.get('Accept-Language')
            activate(request.LANGUAGE_CODE)
        except:
            request.LANGUAGE_CODE = 'en-us'

        response = self.get_response(request)
        return response
