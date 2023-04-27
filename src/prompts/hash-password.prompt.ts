#!/usr/bin/env node
import { PromptObject, prompt } from 'prompts';
import { BcryptHasher } from '../hashers/bcrypt.hasher';

(async () => {
  const questions: PromptObject[] = [
    {
      type: 'password',
      name: 'username',
      message: 'Type in the password you would like to hash:',
    },
  ];

  await prompt(questions, {
    onSubmit: async (_: string, answer: string) =>
      console.log(await new BcryptHasher().hash(answer)),
  });
})();
