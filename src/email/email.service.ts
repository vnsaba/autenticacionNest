import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter;
  private appName: string;
  private appUrl: string;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('EMAIL_HOST'),
      port: this.configService.get('EMAIL_PORT'),
      secure: this.configService.get('EMAIL_SECURE') === 'true',
      auth: {
        user: this.configService.get('EMAIL_USER'),
        pass: this.configService.get('EMAIL_PASSWORD'),
      },
    });

    this.appName = this.configService.get('APP_NAME') || 'Backend UAM';
    this.appUrl = this.configService.get('APP_URL') || 'https://backend-uam.com';
  }

  async sendVerificationEmail(
    email: string,
    name: string,
    code: string,
  ): Promise<void> {
    const mailOptions = {
      from: `"${this.appName}" <${this.configService.get('EMAIL_USER')}>`,
      to: email,
      subject: 'Verifica tu dirección de correo electrónico',
      html: this.getVerificationEmailTemplate(name, code),
    };

    await this.transporter.sendMail(mailOptions);
  }

  private getVerificationEmailTemplate(name: string, code: string): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>Verificación de correo</title>
        </head>
        <body>
          <p>Hola ${name},</p>
          <p>Gracias por registrarte en ${this.appName}.</p>
          <p>Por favor, usa el siguiente código para verificar tu dirección de correo electrónico:</p>
          <h2>${code}</h2>
          <p>O haz clic en el siguiente enlace para verificar tu correo:</p>
          <a href="${this.appUrl}/verify?code=${code}">${this.appUrl}/verify?code=${code}</a>
          <p>Si no solicitaste esto, puedes ignorar este mensaje.</p>
          <p>Saludos,<br/>El equipo de ${this.appName}</p>
        </body>
      </html>
    `;
  }
}
