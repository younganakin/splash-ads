from django.http import HttpResponse
from django.urls import reverse
from django.http import HttpResponseRedirect
from .models import Radcheck
from .models import Radreply
from .generate import TOTPVerification
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

import requests
import json

totp_verification = TOTPVerification()


def index(request):
    login_url = request.GET.get('login_url', '')
    continue_url = request.GET.get('continue_url', '')
    ap_name = request.GET.get('ap_name', '')
    ap_mac = request.GET.get('ap_mac', '')
    ap_tags = request.GET.get('ap_tags', '')
    client_ip = request.GET.get('client_ip', '')
    client_mac = request.GET.get('client_mac', '')

    request.session['login_url'] = login_url
    request.session['continue_url'] = continue_url
    request.session['ap_name'] = ap_name
    request.session['ap_mac'] = ap_mac
    request.session['ap_tags'] = ap_tags
    request.session['client_ip'] = client_ip
    request.session['client_mac'] = client_mac

    url = 'http://' + request.get_host() + \
        reverse('ads:check-credentials')

    context = {
        'url': url,
    }

    return render(request, 'ads/index.html', context)


def check_credentials(request):
    try:
        client_mac = request.session['client_mac']
        radcheck = Radcheck.objects.get(mac_address=client_mac,
                                        organization='ads')
        login_url = request.session['login_url']
        continue_url = request.session['continue_url']
        login_params = {"username": radcheck.username,
                        "password": radcheck.value,
                        "success_url": continue_url}
        r = requests.post(login_url, params=login_params)
        return HttpResponseRedirect(r.url)
    except Radcheck.DoesNotExist:
        return HttpResponseRedirect(reverse('ads:signup'))


@csrf_exempt
def signup(request):
    if request.method == 'POST':
        phone_number = request.POST['phone_number']
        client_mac = request.session['client_mac']
        generated_token = totp_verification.generate_token()
        username = phone_number + client_mac + 'ads'
        radcheck = Radcheck(username=username,
                            attribute='Cleartext-Password',
                            op=':=',
                            value=generated_token,
                            phone_number=phone_number,
                            mac_address=client_mac,
                            organization='ads')

        radreply = Radreply(username=username,
                            attribute='Session-Timeout',
                            op='=',
                            value='60')
        radcheck.save()
        radreply.save()

        sms_url = 'http://pay.brandfi.co.ke:8301/sms/send'
        welcome_message = 'Online access code is: ' + generated_token
        sms_params = {
            "clientId": "2",
            "message": welcome_message,
            "recepients": phone_number
        }
        headers = {'Content-type': 'application/json'}
        sms_r = requests.post(
            sms_url,
            json=sms_params,
            headers=headers)
        return HttpResponseRedirect(reverse('ads:verify'))
    return render(request, 'ads/signup.html')


@csrf_exempt
def verify(request):
    if request.method == 'POST':
        password = request.POST['password']
        radcheck = Radcheck.objects.get(value=password)

        login_url = request.session['login_url']
        continue_url = request.session['continue_url']
        login_params = {"username": radcheck.username,
                        "password": radcheck.value,
                        "success_url": continue_url}
        r = requests.post(login_url, params=login_params)
        return HttpResponseRedirect(r.url)
    return render(request, 'ads/verify.html')
