package note.counter;

public class NoteCounter {

    public static void main(String[] args) {
        try{
            String test1 = note.counter.DataCipher.AESCipherPass.encrypt("ttes","test");
            System.out.println(test1);
        } catch(Exception e){
            System.out.println("error");
        }
    }
}
