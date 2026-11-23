"""sheaf-approve: the page where a person approves a staged mandate change (standard 7.6).

It holds no Azure credential and keeps nothing: the person's own Entra ID token, held in their
browser, is the only authority it uses, relayed to the gateway for each request.
"""
