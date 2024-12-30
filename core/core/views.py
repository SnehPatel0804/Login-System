from django.shortcuts import render
from .models import Product
from django.contrib.auth.decorators import login_required







@login_required
def home_view(request):
    return render(request, 'pages/home.html')






def product_list(request):
    products = Product.objects.all()  # Fetch all products
    return render(request, 'pages/product_list.html', {'products': products})





