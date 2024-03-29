<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class UserFixtures extends Fixture
{
    private $passwordEncoder;

    public function __construct(UserPasswordEncoderInterface $passwordEncoder){
        $this->passwordEncoder = $passwordEncoder;
    }

    public function load(ObjectManager $manager)
    {
        $user = new User();
        $user->setLogin("clement.desavis")
            ->setPassword($this->passwordEncoder->encodePassword($user, 'password'))
            ->setRoles(['ROLE_USER'])
            ->setEmail("clement.desavis@email.com")
        ;

        $manager->persist($user);
        $manager->flush();
    }
}
