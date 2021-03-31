<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\FactorType;
use App\Form\TokenType;
use Swift_Mailer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\IntegerType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    /**
     * @Route("/", name="app_login")
     * @param AuthenticationUtils $authenticationUtils
     * @return Response
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    /**
     * @Route("/tokenValidation", name="check_token")
     * @param Swift_Mailer $mailer
     * @param Request $request
     * @return Response
     */
    public function checkToken(Swift_Mailer $mailer, Request $request){
        $user = $this->getDoctrine()->getRepository(User::class)->findOneBy(['login'=> $this->getUser()->getUsername()]);

        //create token and send mail


        if($request->request->count() > 0){
            $token = $request->request->get('token');
            $isvalid = $this->checkValidity($user->getId(),$token["token"]);

            if($isvalid){
                return $this->redirectToRoute('home');
            }else {
                return $this->redirectToRoute('app_logout');
            }
        }else{
            $this->createToken($user, $mailer);
        }


        //check if token enter is valid & NOW < CREATION + 30min
        $form = $this->createForm(TokenType::class);

        $form->handleRequest($request);

        $user = $this->getDoctrine()->getRepository(User::class)->findOneBy(['login'=> $this->getUser()->getUsername()]);

        return $this->render('security/factor.html.twig', [
            'form' => $form->createView()
        ]);
    }

    private function createToken($user, $mailer){
        $token = rand(100000,999999);

        $user->setToken($token);
        $user->setTokenCreationDate(new \DateTime('now'));

        $this->getDoctrine()->getManager()->persist($user);
        $this->getDoctrine()->getManager()->flush();

        $email = (new \Swift_Message())
            ->setFrom('auth.2.facteurs@mail.com')
            ->setTo($user->getEmail())
            ->setBody($token)
        ;

        $mailer->send($email);

    }

    private function checkValidity($id, $token){
        $user = $this->getDoctrine()->getRepository(User::class)->find($id);

        $expirationDate = $user->getTokenCreationDate();
        $expirationDate->add(New \DateInterval('PT' . 30 . 'M'));
        $now = new \DateTime('now');

        //dd([$token, $user->getToken(),$expirationDate, $now]);

        if($user->getToken() == $token){
            //dd([$token, $user->getToken(),$expirationDate, $now]);

            $user->setToken(null);
            $this->getDoctrine()->getManager()->persist($user);
            $this->getDoctrine()->getManager()->flush();

            return true;
        }
        else{
            return false;
        }

    }

}
