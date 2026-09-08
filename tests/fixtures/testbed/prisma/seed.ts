import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const seedUsers = [
  {
    username: "halo_admin",
    email: "halo_admin@example.com",
    password: "HaloAdmin_123!",
    role: "admin",
  },
  {
    username: "halo_user_a",
    email: "halo_user_a@example.com",
    password: "HaloUserA_123!",
    role: "user",
  },
  {
    username: "halo_user_b",
    email: "halo_user_b@example.com",
    password: "HaloUserB_123!",
    role: "user",
  },
];

async function main() {
  const admin = await prisma.user.upsert({
    where: { email: seedUsers[0].email },
    update: {},
    create: seedUsers[0],
  });

  const userA = await prisma.user.upsert({
    where: { email: seedUsers[1].email },
    update: {},
    create: seedUsers[1],
  });

  const userB = await prisma.user.upsert({
    where: { email: seedUsers[2].email },
    update: {},
    create: seedUsers[2],
  });

  // Plant victim invoice for BOLA testing
  await prisma.invoice.upsert({
    where: { id: "inv-b-1" },
    update: {},
    create: {
      id: "inv-b-1",
      title: "Confidential Invoice B",
      amount: 450.0,
      userId: userB.id,
    },
  });

  // Plant unpaid order for workflow bypass testing
  await prisma.order.upsert({
    where: { id: "1" },
    update: {},
    create: {
      id: "1",
      status: "created",
      paid: false,
      total: 100.0,
      userId: userA.id,
    },
  });

  // Plant single-use coupon for race condition testing
  await prisma.coupon.upsert({
    where: { code: "DISCOUNT50" },
    update: {},
    create: {
      id: "coup-1",
      code: "DISCOUNT50",
      discount: 50.0,
      used: false,
      redeemCount: 0,
    },
  });

  console.log("Seed completed successfully.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
