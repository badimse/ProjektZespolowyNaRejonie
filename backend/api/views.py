import stripe
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser, BasePermission
from rest_framework.decorators import action
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash


class IsAuthenticatedOrReadOnly(BasePermission):
    """
    Custom permission: pozwala na odczyt każdemu, 
    ale zapis tylko zalogowanym użytkownikom.
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        return request.user and request.user.is_authenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from .serializers import (
    RegisterSerializer, UserSerializer, ProduktSerializer, 
    KoszykSerializer, PozycjaKoszykaSerializer, 
    ZamowienieSerializer, AdresDostawySerializer,
    OpiniaSerializer, PlatnoscSerializer, ZwrotSerializer
)
from .models import (
    Produkt, Koszyk, PozycjaKoszyka, Zamowienie, 
    PozycjaZamowienia, AdresDostawy, Opinia, 
    Platnosc, Zwrot, RozmiarProduktu
)

User = get_user_model()


class PasswordResetRequestView(APIView):
    """Wysyła link do resetowania hasła na podany adres e-mail."""
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"detail": "E-mail jest wymagany."}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # W środowisku produkcyjnym link powinien prowadzić do frontendu
            # np. frontend_url = f"http://localhost:8080/reset-password.html?uid={uid}&token={token}"
            # W środowisku produkcyjnym zastąp localhost:5500 przez domenę frontendu (np. 'https://narejonie.com.pl')
            frontend_url = f"https://narejonie.com.pl/reset-password.html?uid={uid}&token={token}"
            
            send_mail(
                subject='Resetowanie hasła - NaRejonie',
                message=f'Kliknij w poniższy link, aby zresetować hasło:\n{frontend_url}',
                from_email=settings.DEFAULT_FROM_EMAIL, # Bezpieczniejsze, bierze prosto z settings
                recipient_list=[user.email],
                fail_silently=False,
)
            
        # Zawsze zwracamy 200 OK ze względów bezpieczeństwa (zapobiega to enumeracji użytkowników)
        return Response({"detail": "Jeśli podany e-mail istnieje w bazie, wysłano na niego link do resetu hasła."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """Ustawia nowe hasło na podstawie poprawnego tokenu."""
    permission_classes = (AllowAny,)

    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('password')

        if not uidb64 or not token or not new_password:
            return Response({"detail": "Brakujące dane."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({"detail": "Hasło zostało pomyślnie zresetowane."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Link do resetu hasła jest nieprawidłowy lub wygasł."}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Customizowany widok logowania z walidacją statusu użytkownika."""
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            # Sprawdź status użytkownika
            email = request.data.get('email')
            user = User.objects.filter(email=email).first()
            if user and user.statusUzytkownika == 'zablokowany':
                return Response(
                    {"detail": "Konto jest zablokowane"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
        return response


class RegisterView(generics.CreateAPIView):
    """Widok rejestracji nowego użytkownika."""
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class ProfileView(generics.RetrieveUpdateAPIView):
    """Widok profilu użytkownika."""
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    
    def get_object(self):
        return self.request.user


class ProduktViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla produktów.
    - GET: Lista produktów (filtrowanie po kategorii, kolorze, cenie)
    - POST: Dodawanie produktu (tylko admin)
    - PUT/PATCH: Edycja produktu (tylko admin)
    - DELETE: Usuwanie produktu (tylko admin)
    """
    queryset = Produkt.objects.all()
    serializer_class = ProduktSerializer
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAdminUser()]
        return [AllowAny()]
    
    def get_queryset(self):
        queryset = Produkt.objects.all()
        
        # Filtrowanie po kategorii
        kategoria = self.request.query_params.get('kategoria')
        if kategoria:
            queryset = queryset.filter(kategoria__icontains=kategoria)
        
        # Filtrowanie po kolorze
        kolor = self.request.query_params.get('kolor')
        if kolor:
            queryset = queryset.filter(kolor__icontains=kolor)
        
        # Filtrowanie po rozmiarze
        rozmiar = self.request.query_params.get('rozmiar')
        if rozmiar:
            queryset = queryset.filter(rozmiar=rozmiar)
        
        # Filtrowanie po cenie (min, max)
        cena_min = self.request.query_params.get('cena_min')
        cena_max = self.request.query_params.get('cena_max')
        if cena_min:
            queryset = queryset.filter(cenaBrutto__gte=cena_min)
        if cena_max:
            queryset = queryset.filter(cenaBrutto__lte=cena_max)
        
        # Wyszukiwanie po nazwie
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(nazwa__icontains=search)
        
        return queryset


class KoszykViewSet(viewsets.ViewSet):
    """
    ViewSet dla koszyka zakupowego.
    Implementuje logikę z diagramu sekwencji "dodaj do koszyka".
    """
    permission_classes = (IsAuthenticated,)
    
    @action(detail=False, methods=['get'])
    def pobierz(self, request):
        """Pobierz koszyk użytkownika."""
        koszyk, created = Koszyk.objects.get_or_create(id_uzytkownik=request.user)
        
        # Sprawdź czy rezerwacja nie wygasła (30 minut)
        if koszyk.rezerwacjaDo and koszyk.rezerwacjaDo < timezone.now():
            # Wyczyść koszyk po wygaśnięciu rezerwacji
            koszyk.pozycje.all().delete()
        
        koszyk.przedluz_rezerwacje()
        serializer = KoszykSerializer(koszyk)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def dodaj(self, request):
        """
        Dodaj produkt do koszyka z wybranym rozmiarem.
        Implementuje logikę Upsert z diagramu sekwencji.
        """
        produkt_id = request.data.get('produkt_id')
        ilosc = int(request.data.get('ilosc', 1))
        rozmiar = request.data.get('rozmiar')
        
        if not produkt_id:
            return Response(
                {"detail": "produkt_id jest wymagane"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        produkt = get_object_or_404(Produkt, id_produkt=produkt_id)
        
        # Sprawdź dostępność dla konkretnego rozmiaru
        if rozmiar:
            rozmiar_obj = RozmiarProduktu.objects.filter(
                id_produkt=produkt, rozmiar=rozmiar
            ).first()
            if not rozmiar_obj:
                return Response(
                    {"detail": f"Rozmiar {rozmiar} niedostępny"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            if rozmiar_obj.stanMagazynowy < ilosc:
                return Response(
                    {"detail": "Niewystarczająca ilość towaru w wybranym rozmiarze"}, 
                    status=status.HTTP_409_CONFLICT
                )
        else:
            # Jeśli nie podano rozmiaru, sprawdź całkowity stan
            total_stock = sum(r.stanMagazynowy for r in produkt.rozmiary.all())
            if total_stock < ilosc:
                return Response(
                    {"detail": "Produkt niedostępny w wybranej ilości"}, 
                    status=status.HTTP_409_CONFLICT
                )
        
        with transaction.atomic():
            # Pobierz lub utwórz koszyk (Lazy Creation)
            koszyk, created = Koszyk.objects.get_or_create(id_uzytkownik=request.user)
            koszyk.przedluz_rezerwacje()
            
            # Sprawdź czy produkt z tym rozmiarem jest już w koszyku
            pozycja = PozycjaKoszyka.objects.filter(
                id_koszyk=koszyk, 
                id_produkt=produkt,
                rozmiar=rozmiar
            ).first()
            
            if pozycja:
                # Produkt z tym rozmiarem już jest w koszyku - aktualizuj ilość
                nowa_ilosc = pozycja.ilosc + ilosc
                # Sprawdź dostępność ponownie
                if rozmiar:
                    rozmiar_obj = RozmiarProduktu.objects.select_for_update().get(
                        id_produkt=produkt, rozmiar=rozmiar
                    )
                    if rozmiar_obj.stanMagazynowy < nowa_ilosc:
                        return Response(
                            {"detail": "Niewystarczająca ilość towaru w wybranym rozmiarze"}, 
                            status=status.HTTP_409_CONFLICT
                        )
                pozycja.ilosc = nowa_ilosc
                pozycja.save()
            else:
                # Nowy produkt w koszyku
                PozycjaKoszyka.objects.create(
                    id_koszyk=koszyk,
                    id_produkt=produkt,
                    rozmiar=rozmiar,
                    ilosc=ilosc,
                    cenaJednostkowa=produkt.cenaBrutto
                )
        
        serializer = KoszykSerializer(koszyk)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'])
    def usun_pozycje(self, request):
        """Usuń pozycję z koszyka."""
        pozycja_id = request.data.get('pozycja_id')
        
        if not pozycja_id:
            return Response(
                {"detail": "pozycja_id jest wymagane"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        koszyk = get_object_or_404(Koszyk, id_uzytkownik=request.user)
        pozycja = get_object_or_404(PozycjaKoszyka, id_pozycjakoszyka=pozycja_id, id_koszyk=koszyk)
        pozycja.delete()
        
        serializer = KoszykSerializer(koszyk)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def aktualizuj_ilosc(self, request):
        """Aktualizuj ilość produktu w koszyku."""
        pozycja_id = request.data.get('pozycja_id')
        ilosc = int(request.data.get('ilosc', 1))
        
        if ilosc < 1:
            return Response(
                {"detail": "Ilość musi być większa niż 0"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        koszyk = get_object_or_404(Koszyk, id_uzytkownik=request.user)
        pozycja = get_object_or_404(PozycjaKoszyka, id_pozycjakoszyka=pozycja_id, id_koszyk=koszyk)
        
        total_stock = sum(r.stanMagazynowy for r in pozycja.id_produkt.rozmiary.all())
        if total_stock < ilosc:
            return Response(
                {"detail": "Niewystarczająca ilość towaru"}, 
                status=status.HTTP_409_CONFLICT
            )
        
        pozycja.ilosc = ilosc
        pozycja.save()
        
        serializer = KoszykSerializer(koszyk)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def wyczysc(self, request):
        """Wyczyść cały koszyk."""
        koszyk, created = Koszyk.objects.get_or_create(id_uzytkownik=request.user)
        koszyk.pozycje.all().delete()
        
        serializer = KoszykSerializer(koszyk)
        return Response(serializer.data)


class ZamowienieViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla zamówień.
    Implementuje proces składania zamówienia z diagramu sekwencji.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = ZamowienieSerializer
    
    def get_queryset(self):
        if self.request.user.is_staff:
            return Zamowienie.objects.all()
        return Zamowienie.objects.filter(id_uzytkownik=self.request.user)
    
    @action(detail=False, methods=['post'])
    def checkout(self, request):
        """
        Złożenie zamówienia i wygenerowanie linku do płatności Stripe.
        """
        koszyk = get_object_or_404(Koszyk, id_uzytkownik=request.user)
        pozycje_koszyka = koszyk.pozycje.all()
        
        if not pozycje_koszyka.exists():
            return Response(
                {"detail": "Koszyk jest pusty"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        adres_data = request.data.get('adres')
        if not adres_data:
            return Response(
                {"detail": "Dane adresowe (adres) są wymagane"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        adres_serializer = AdresDostawySerializer(data=adres_data)
        if not adres_serializer.is_valid():
            return Response(
                adres_serializer.errors, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            line_items = [] # <-- Lista produktów dla Stripe
            
            with transaction.atomic():
                kwota_calkowita = 0
                
                # Sprawdzanie dostępności
                for pozycja in pozycje_koszyka:
                    produkt = Produkt.objects.select_for_update().get(
                        id_produkt=pozycja.id_produkt_id
                    )
                    total_stock = sum(r.stanMagazynowy for r in produkt.rozmiary.select_for_update().all())
                    if total_stock < pozycja.ilosc:
                        raise ValueError(
                            f"Niewystarczająca ilość produktu: {produkt.nazwa}"
                        )
                    
                    kwota_calkowita += pozycja.ilosc * pozycja.cenaJednostkowa
                
                # Utwórz zamówienie w bazie (pozostaje jako "oczekujące")
                zamowienie = Zamowienie.objects.create(
                    id_uzytkownik=request.user,
                    status='oczekujące',
                    kwota=kwota_calkowita
                )
                
                adres_serializer.save(id_zamowienie=zamowienie)
                
                # Przepisanie pozycji i budowanie listy dla Stripe
                for pozycja in pozycje_koszyka:
                    PozycjaZamowienia.objects.create(
                        id_zamowienie=zamowienie,
                        id_produkt=pozycja.id_produkt,
                        ilosc=pozycja.ilosc,
                        cenaJednostkowa=pozycja.cenaJednostkowa
                    )
                    
                    # DODANE: Budujemy element koszyka dla Stripe
                    # Stripe wymaga podania ceny w najmniejszej jednostce (czyli w groszach)
                    line_items.append({
                        'price_data': {
                            'currency': 'pln',
                            'product_data': {
                                'name': pozycja.id_produkt.nazwa,
                            },
                            'unit_amount': int(pozycja.cenaJednostkowa * 100), 
                        },
                        'quantity': pozycja.ilosc,
                    })
                    
                    # Zmniejszanie stanu magazynowego
                    produkt = pozycja.id_produkt
                    ilosc_do_odjecia = pozycja.ilosc
                    for rozmiar in produkt.rozmiary.select_for_update().all():
                        if ilosc_do_odjecia <= 0:
                            break
                        if rozmiar.stanMagazynowy > 0:
                            if rozmiar.stanMagazynowy >= ilosc_do_odjecia:
                                rozmiar.stanMagazynowy -= ilosc_do_odjecia
                                rozmiar.save()
                                ilosc_do_odjecia = 0
                            else:
                                ilosc_do_odjecia -= rozmiar.stanMagazynowy
                                rozmiar.stanMagazynowy = 0
                                rozmiar.save()
                
                # Wyczyść koszyk na sam koniec
                pozycje_koszyka.delete()

            # --- INTEGRACJA Z BRAMKĄ STRIPE ---
            # Definiujemy gdzie Stripe ma odesłać klienta po płatności (sukces lub błąd)
            domain_url = "https://narejonie.com.pl"
            
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card', 'blik', 'p24'], # Włączamy Blika i Przelewy24!
                line_items=line_items,
                mode='payment',
                success_url=domain_url + '/index.html?payment=success', # Możesz dorobić później dedykowaną stronę
                cancel_url=domain_url + '/index.html?payment=cancelled',
                client_reference_id=str(zamowienie.id_zamowienie),
                customer_email=request.user.email, # Opcjonalnie, wstawia maila klienta do formularza płatności
            )

        except ValueError as e:
            return Response(
                {"detail": str(e)}, 
                status=status.HTTP_409_CONFLICT
            )
        except stripe.error.StripeError as e:
            # Gdyby Stripe miał awarię (np. błędny klucz API)
            return Response(
                {"detail": f"Błąd bramki płatności: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        serializer = self.get_serializer(zamowienie)
        
        # ZWRACAMY NOWY LINK DO PŁATNOŚCI
        return Response({
            'zamowienie': serializer.data,
            'checkout_url': checkout_session.url
        }, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def anuluj(self, request, pk=None):
        """Anuluj zamówienie (tylko jeśli jest w statusie 'oczekujące')."""
        zamowienie = self.get_object()
        
        # Sprawdź czy użytkownik ma prawo anulować
        if zamowienie.id_uzytkownik != request.user and not request.user.is_staff:
            return Response(
                {"detail": "Brak uprawnień"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        if zamowienie.status != 'oczekujące':
            return Response(
                {"detail": "Można anulować tylko zamówienia oczekujące"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        zamowienie.status = 'anulowane'
        zamowienie.save()
        
        serializer = self.get_serializer(zamowienie)
        return Response(serializer.data)


class ZamowienieAdminViewSet(viewsets.ViewSet):
    """
    ViewSet dla administratora do zarządzania zamówieniami.
    """
    permission_classes = (IsAdminUser,)
    
    @action(detail=False, methods=['get'])
    def do_realizacji(self, request):
        """Pobierz zamówienia oczekujące na realizację."""
        zamowienia = Zamowienie.objects.filter(status='oczekujące')
        serializer = ZamowienieSerializer(zamowienia, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['patch'])
    def zmien_status(self, request, pk=None):
        """Zmień status zamówienia."""
        zamowienie = get_object_or_404(Zamowienie, id_zamowienie=pk)
        nowy_status = request.data.get('status')
        
        valid_statuses = ['oczekujące', 'w realizacji', 'wysłane', 'zakończone', 'anulowane']
        if nowy_status not in valid_statuses:
            return Response(
                {"detail": "Nieprawidłowy status"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        zamowienie.status = nowy_status
        zamowienie.save()
        
        serializer = ZamowienieSerializer(zamowienie)
        return Response(serializer.data)


class OpiniaViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla opinii o produktach.
    """
    queryset = Opinia.objects.all()
    serializer_class = OpiniaSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)

        # Pobieramy ID produktu  
    def get_queryset(self):
        id_produkt = self.request.query_params.get('id_produkt')
        
        if id_produkt:
            return Opinia.objects.filter(id_produkt=id_produkt)
        
        return Opinia.objects.none()
    
    def perform_create(self, serializer):
        serializer.save(id_uzytkownik=self.request.user)


class ZwrotViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla zwrotów produktów.
    """
    queryset = Zwrot.objects.all()
    serializer_class = ZwrotSerializer
    permission_classes = (IsAuthenticated,)
    
    def get_queryset(self):
        if self.request.user.is_staff:
            return Zwrot.objects.all()
        # Użytkownik widzi tylko swoje zwroty
        zamowienia_ids = Zamowienie.objects.filter(
            id_uzytkownik=self.request.user
        ).values_list('id_zamowienie', flat=True)
        return Zwrot.objects.filter(id_zamowienie__in=zamowienia_ids)
    
    def create(self, request, *args, **kwargs):
        """
        Zgłoś zwrot produktu.
        Walidacja: zamówienie musi być w statusie 'zakończone' 
        i nie może minąć 14 dni od dostawy.
        """
        id_zamowienie = request.data.get('id_zamowienie')
        zamowienie = get_object_or_404(Zamowienie, id_zamowienie=id_zamowienie)
        
        # Sprawdź czy użytkownik jest właścicielem zamówienia
        if zamowienie.id_uzytkownik != request.user:
            return Response(
                {"detail": "Brak uprawnień do tego zamówienia"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Sprawdź status zamówienia
        if zamowienie.status != 'zakończone':
            return Response(
                {"detail": "Zwrot możliwy tylko dla zakończonych zamówień"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Sprawdź czy nie minęło 14 dni
        dni_od_zamowienia = (timezone.now() - zamowienie.dataZlozenia).days
        if dni_od_zamowienia > 14:
            return Response(
                {"detail": "Minął termin 14 dni na zwrot"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Sprawdź czy nie ma już zwrotu dla tego zamówienia
        if Zwrot.objects.filter(id_zamowienie=zamowienie).exists():
            return Response(
                {"detail": "Zwrot dla tego zamówienia już został zgłoszony"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return super().create(request, *args, **kwargs)


class ZwrotAdminViewSet(viewsets.ViewSet):
    """
    ViewSet dla administratora do obsługi zwrotów.
    """
    permission_classes = (IsAdminUser,)
    
    def list(self, request):
        """Lista wszystkich zwrotów."""
        zwroty = Zwrot.objects.all().order_by('-dataZgloszenia')
        serializer = ZwrotSerializer(zwroty, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def zatwierdz(self, request, pk=None):
        """Zatwierdź zwrot."""
        zwrot = get_object_or_404(Zwrot, id_zwrot=pk)
        zwrot.status = 'przyjęty'
        zwrot.save()
        
        serializer = ZwrotSerializer(zwrot)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def odrzuc(self, request, pk=None):
        """Odrzuć zwrot."""
        zwrot = get_object_or_404(Zwrot, id_zwrot=pk)
        zwrot.status = 'odrzucony'
        zwrot.save()
        
        serializer = ZwrotSerializer(zwrot)
        return Response(serializer.data)


class UserAdminViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla administratora do zarządzania użytkownikami.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = User.objects.all()
        
        # Filtrowanie po statusie
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(statusUzytkownika=status)
        
        # Filtrowanie po emailu
        email = self.request.query_params.get('email')
        if email:
            queryset = queryset.filter(email__icontains=email)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def zablokuj(self, request, pk=None):
        """Zablokuj użytkownika."""
        user = get_object_or_404(User, id=pk)
        user.statusUzytkownika = 'zablokowany'
        user.save()
        return Response({'detail': 'Użytkownik zablokowany'})
    
    @action(detail=True, methods=['post'])
    def odblokuj(self, request, pk=None):
        """Odblokuj użytkownika."""
        user = get_object_or_404(User, id=pk)
        user.statusUzytkownika = 'aktywny'
        user.save()
        return Response({'detail': 'Użytkownik odblokowany'})
    
    @action(detail=True, methods=['post'])
    def usun(self, request, pk=None):
        """Miękkie usuwanie użytkownika (zmiana statusu)."""
        user = get_object_or_404(User, id=pk)
        
        if user == request.user:
            return Response(
                {'detail': 'Nie możesz usunąć własnego konta administratora.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user.statusUzytkownika = 'usunięty'
        user.is_active = False # Blokuje całkowicie możliwość logowania w Django
        user.save()
        
        return Response({'detail': 'Użytkownik oznaczony jako usunięty'})

class OpiniaAdminViewSet(viewsets.ModelViewSet):
    """
    ViewSet dla administratora do zarządzania opiniami.
    """
    queryset = Opinia.objects.all()
    serializer_class = OpiniaSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = Opinia.objects.all()
        
        # Filtrowanie po produkcie
        id_produkt = self.request.query_params.get('id_produkt')
        if id_produkt:
            queryset = queryset.filter(id_produkt=id_produkt)
        
        # Filtrowanie po użytkowniku
        id_uzytkownik = self.request.query_params.get('id_uzytkownik')
        if id_uzytkownik:
            queryset = queryset.filter(id_uzytkownik=id_uzytkownik)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def usun(self, request, pk=None):
        """Usuń opinię."""
        opinia = get_object_or_404(Opinia, id_opinia=pk)
        opinia.delete()
        return Response({'detail': 'Opinia usunięta'})
    
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated] # Tylko zalogowani mogą zmieniać hasło

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        # 1. Sprawdź czy stare hasło jest poprawne
        if not user.check_password(old_password):
            return Response(
                {"detail": "Obecne hasło jest nieprawidłowe."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2. Ustaw nowe hasło (Django automatycznie je zahaszuje)
        user.set_password(new_password)
        user.save()

        # 3. Ważne: aktualizacja sesji, aby użytkownik nie został wylogowany
        update_session_auth_hash(request, user)

        return Response(
            {"detail": "Hasło zostało pomyślnie zmienione."}, 
            status=status.HTTP_200_OK)

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import os
import stripe
from .models import Zamowienie

@csrf_exempt
def stripe_webhook(request):
    """
    Funkcja odbierająca ciche powiadomienia (Webhooki) ze Stripe.
    """
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

    try:
        # Stripe weryfikuje, czy to na pewno on wysłał to zapytanie (bezpieczeństwo!)
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Błędny payload
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        # Błędny podpis (próba oszustwa)
        return HttpResponse(status=400)

    # Jeśli płatność zakończyła się pełnym sukcesem
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Wyciągamy nasz numer zamówienia, który podaliśmy w checkout_session
        zamowienie_id = session.client_reference_id

        if zamowienie_id:
            try:
                zamowienie = Zamowienie.objects.get(id_zamowienie=zamowienie_id)
                # ZMIANA STATUSU PO OPŁACENIU!
                # Zmieniamy status na "w realizacji", co oznacza dla admina: "Opłacone, pakuj towar!"
                zamowienie.status = 'w realizacji'
                zamowienie.save()
            except Zamowienie.DoesNotExist:
                pass

    return HttpResponse(status=200)